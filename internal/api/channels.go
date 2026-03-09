// ABOUTME: HTTP handlers for notification channel CRUD and signing secret rotation.
// ABOUTME: signing_secret is returned only on create and rotate-secret responses — never on GET/LIST/PATCH.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/tier"
)

// ── Request / response types ──────────────────────────────────────────────────

type createChannelBody struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// patchChannelBody uses pointer fields so only supplied keys are updated.
type patchChannelBody struct {
	Name   *string          `json:"name"`
	Config *json.RawMessage `json:"config"`
}

type channelEntry struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

// channelCreateEntry extends channelEntry with the signing secret, returned only at creation.
type channelCreateEntry struct {
	channelEntry
	SigningSecret string `json:"signing_secret"`
}

type channelListResponse struct {
	Items []channelEntry `json:"items"`
}

type rotateSecretResponse struct {
	SigningSecret string `json:"signing_secret"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// createChannelHandler handles POST /api/v1/orgs/{org_id}/channels.
// Returns 201 with the channel and its signing_secret (shown only once).
func (srv *Server) createChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createChannelBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		http.Error(w, "name is required", http.StatusUnprocessableEntity)
		return
	}
	if req.Type == "" {
		req.Type = "webhook"
	}
	if req.Type != "webhook" && req.Type != "email" {
		http.Error(w, "type must be 'webhook' or 'email'", http.StatusUnprocessableEntity)
		return
	}

	// Tier gating: check channel type availability.
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "tier resolver missing from context")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !resolver.BoolFlag("channels_"+req.Type, req.Type == "webhook", true, true) {
		srv.auditLog(r, audit.Entry{
			OrgID:      orgID,
			Action:     "create",
			EntityType: "channel",
			EntityName: req.Name,
			Success:    false,
			Metadata:   map[string]any{"reason": "tier_limit", "channel_type": req.Type},
		})
		http.Error(w, "tier limit: channel type not available", http.StatusForbidden)
		return
	}

	// For webhook channels, validate that config contains a non-empty, SSRF-safe url.
	if req.Type == "webhook" {
		var cfg map[string]any
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			http.Error(w, "webhook config must include a non-empty url", http.StatusUnprocessableEntity)
			return
		}
		urlVal, ok := cfg["url"].(string)
		if !ok || strings.TrimSpace(urlVal) == "" {
			http.Error(w, "webhook config must include a non-empty url", http.StatusUnprocessableEntity)
			return
		}
		if err := validateWebhookURL(urlVal); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	if req.Type == "email" {
		if _, err := validateEmailConfig(req.Config); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	row, secret, err := srv.store.CreateNotificationChannel(r.Context(), orgID, req.Name, req.Type, req.Config)
	if err != nil {
		slog.ErrorContext(r.Context(), "create notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entry := channelEntry{
		ID:        row.ID.String(),
		OrgID:     row.OrgID.String(),
		Name:      row.Name,
		Type:      row.Type,
		Config:    row.Config,
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	}
	if req.Type == "webhook" {
		writeJSON(w, http.StatusCreated, channelCreateEntry{
			channelEntry: entry,
			SigningSecret: secret,
		})
	} else {
		writeJSON(w, http.StatusCreated, entry)
	}

	// Build audit state with config fields at top level for proper redaction.
	newState := channelAuditState(row.Name, row.Type, row.Config)
	if req.Type == "webhook" {
		newState["signing_secret"] = secret
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "create",
		EntityType: "channel",
		EntityID:   row.ID.String(),
		EntityName: row.Name,
		Success:    true,
		NewState:   newState,
	})
}

// getChannelHandler handles GET /api/v1/orgs/{org_id}/channels/{id}.
func (srv *Server) getChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	row, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, channelEntry{
		ID:        row.ID.String(),
		OrgID:     row.OrgID.String(),
		Name:      row.Name,
		Type:      row.Type,
		Config:    row.Config,
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	})
}

// listChannelsHandler handles GET /api/v1/orgs/{org_id}/channels.
func (srv *Server) listChannelsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	rows, err := srv.store.ListNotificationChannels(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list notification channels", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	items := make([]channelEntry, len(rows))
	for i, row := range rows {
		items[i] = channelEntry{
			ID:        row.ID.String(),
			OrgID:     row.OrgID.String(),
			Name:      row.Name,
			Type:      row.Type,
			Config:    row.Config,
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
			UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
		}
	}
	writeJSON(w, http.StatusOK, channelListResponse{Items: items})
}

// patchChannelHandler handles PATCH /api/v1/orgs/{org_id}/channels/{id}.
// Only supplied fields are updated; absent fields preserve existing values.
func (srv *Server) patchChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	var req patchChannelBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Fetch current row to preserve unpatched fields.
	current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel for patch", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	oldState := channelAuditState(current.Name, current.Type, current.Config)

	params := store.UpdateNotificationChannelParams{
		Name:   current.Name,
		Config: current.Config,
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			http.Error(w, "name must not be empty or whitespace", http.StatusUnprocessableEntity)
			return
		}
		params.Name = *req.Name
	}
	if req.Config != nil {
		// Re-validate config when updated.
		if current.Type == "webhook" {
			var cfg map[string]any
			if err := json.Unmarshal(*req.Config, &cfg); err != nil {
				http.Error(w, "webhook config must be valid JSON with a url field", http.StatusUnprocessableEntity)
				return
			}
			urlVal, ok := cfg["url"].(string)
			if !ok || strings.TrimSpace(urlVal) == "" {
				http.Error(w, "webhook config must include a non-empty url", http.StatusUnprocessableEntity)
				return
			}
			if err := validateWebhookURL(urlVal); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
		}
		if current.Type == "email" {
			if _, err := validateEmailConfig(*req.Config); err != nil {
				http.Error(w, err.Error(), http.StatusUnprocessableEntity)
				return
			}
		}
		params.Config = *req.Config
	}

	updated, err := srv.store.UpdateNotificationChannel(r.Context(), orgID, id, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "update notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if updated == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, channelEntry{
		ID:        updated.ID.String(),
		OrgID:     updated.OrgID.String(),
		Name:      updated.Name,
		Type:      updated.Type,
		Config:    updated.Config,
		CreatedAt: updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt: updated.UpdatedAt.Format(time.RFC3339),
	})
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "channel",
		EntityID:   id.String(),
		EntityName: updated.Name,
		Success:    true,
		OldState:   oldState,
		NewState:   channelAuditState(updated.Name, updated.Type, updated.Config),
	})
}

// deleteChannelHandler handles DELETE /api/v1/orgs/{org_id}/channels/{id}.
// Returns 409 if the channel has active bound rules; 204 on success.
func (srv *Server) deleteChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Fetch before delete for audit log.
	current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for delete", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	hasBindings, err := srv.store.ChannelHasActiveBindings(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "check channel active bindings", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if hasBindings {
		http.Error(w, "channel has active bound rules or reports", http.StatusConflict)
		return
	}

	if err := srv.store.SoftDeleteNotificationChannel(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "soft delete notification channel", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "channel",
		EntityID:   id.String(),
		EntityName: current.Name,
		Success:    true,
		OldState:   channelAuditState(current.Name, current.Type, current.Config),
	})
	w.WriteHeader(http.StatusNoContent)
}

// rotateSecretHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/rotate-secret.
// Promotes the current primary to secondary, generates a new primary, returns it once.
func (srv *Server) rotateSecretHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for rotate", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ch == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if ch.Type != "webhook" {
		http.Error(w, "signing secret operations are only available for webhook channels", http.StatusUnprocessableEntity)
		return
	}

	secret, err := srv.store.RotateSigningSecret(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "rotate signing secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if secret == "" {
		// Channel was deleted between GET and rotate (TOCTOU).
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, rotateSecretResponse{SigningSecret: secret})
}

// clearSecondarySecretHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/clear-secondary.
// Clears the secondary signing secret once all consumers have migrated to the new primary.
func (srv *Server) clearSecondarySecretHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for clear-secondary", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ch == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if ch.Type != "webhook" {
		http.Error(w, "signing secret operations are only available for webhook channels", http.StatusUnprocessableEntity)
		return
	}

	if err := srv.store.ClearSecondarySecret(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "clear secondary secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type testChannelResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// testChannelHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/test.
// Sends a test notification through the channel and reports success/failure.
// Always returns 200; delivery outcome is in the response body.
func (srv *Server) testChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	// Verify channel exists and belongs to this org.
	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for test", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ch == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	var testErr error
	switch ch.Type {
	case "webhook":
		testErr = srv.testWebhookChannel(r.Context(), id)
	case "email":
		testErr = srv.testEmailChannel(r.Context(), ch.Config)
	default:
		http.Error(w, "unsupported channel type", http.StatusUnprocessableEntity)
		return
	}

	resp := testChannelResponse{Success: testErr == nil}
	if testErr != nil {
		resp.Error = testErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (srv *Server) testWebhookChannel(ctx context.Context, channelID uuid.UUID) error {
	delivery, err := srv.store.GetNotificationChannelForDelivery(ctx, channelID)
	if err != nil {
		return fmt.Errorf("load channel: %w", err)
	}
	if delivery == nil {
		return errors.New("channel not found")
	}

	var cfg map[string]any
	_ = json.Unmarshal(delivery.Config, &cfg)
	urlStr, _ := cfg["url"].(string)

	client, err := notify.BuildSafeClient()
	if err != nil {
		return fmt.Errorf("build webhook client: %w", err)
	}

	payload, _ := json.Marshal(map[string]any{
		"test":      true,
		"message":   "Test notification from CVErt Ops",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	whCfg := notify.WebhookConfig{
		URL:                    urlStr,
		SigningSecret:          delivery.SigningSecret.String,
		SigningSecretSecondary: delivery.SigningSecretSecondary.String,
	}
	// Apply custom headers if present.
	if headers, ok := cfg["headers"].(map[string]any); ok {
		whCfg.CustomHeaders = make(map[string]string, len(headers))
		for k, v := range headers {
			if s, ok := v.(string); ok {
				whCfg.CustomHeaders[k] = s
			}
		}
	}

	return notify.Send(ctx, client, whCfg, payload)
}

func (srv *Server) testEmailChannel(ctx context.Context, config json.RawMessage) error {
	if srv.cfg.SMTPHost == "" {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST to enable email delivery")
	}

	recipients, err := validateEmailConfig(config)
	if err != nil {
		return err
	}

	smtpCfg := notify.SmtpConfig{
		Host:     srv.cfg.SMTPHost,
		Port:     srv.cfg.SMTPPort,
		From:     srv.cfg.SMTPFrom,
		Username: srv.cfg.SMTPUsername,
		Password: srv.cfg.SMTPPassword,
		TLS:      srv.cfg.SMTPTLS,
	}

	subject := "CVErt Ops — Test Notification"
	htmlBody := "<p>This is a test notification from CVErt Ops. If you received this, your email channel is configured correctly.</p>"
	textBody := "This is a test notification from CVErt Ops. If you received this, your email channel is configured correctly."

	return notify.EmailSend(ctx, smtpCfg, recipients, subject, htmlBody, textBody)
}

// channelAuditState builds a flat map for audit log state, merging config fields
// at the top level so redactSecrets can process the URL for channel entities.
func channelAuditState(name, chType string, config json.RawMessage) map[string]any {
	state := map[string]any{
		"name": name,
		"type": chType,
	}
	var cfgMap map[string]any
	if err := json.Unmarshal(config, &cfgMap); err == nil {
		for k, v := range cfgMap {
			state[k] = v
		}
	}
	return state
}

// validateEmailConfig validates email channel config:
// - recipients must be non-empty, max 50, valid RFC 5322 addresses, no duplicates.
func validateEmailConfig(config json.RawMessage) ([]string, error) {
	var cfg struct {
		Recipients []string `json:"recipients"`
	}
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, errors.New("email config must include a recipients array")
	}
	if len(cfg.Recipients) == 0 {
		return nil, errors.New("email config must include at least one recipient")
	}
	if len(cfg.Recipients) > 50 {
		return nil, errors.New("email config must not exceed 50 recipients")
	}
	seen := make(map[string]bool, len(cfg.Recipients))
	for _, r := range cfg.Recipients {
		addr, err := mail.ParseAddress(r)
		if err != nil {
			return nil, fmt.Errorf("invalid email recipient %q: %w", r, err)
		}
		normalized := strings.ToLower(addr.Address)
		if seen[normalized] {
			return nil, fmt.Errorf("duplicate email recipient: %s", normalized)
		}
		seen[normalized] = true
	}
	return cfg.Recipients, nil
}

// validateWebhookURL performs SSRF-safe static validation of a webhook URL at registration time.
// Dynamic validation occurs again at delivery time via the safeurl-wrapped client.
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errors.New("webhook url is not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("webhook url must use http or https scheme")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("webhook url must have a host")
	}
	// Reject known-internal hostnames.
	lh := strings.ToLower(host)
	if lh == "localhost" || strings.HasSuffix(lh, ".local") || strings.HasSuffix(lh, ".internal") {
		return errors.New("webhook url must not target private or internal addresses")
	}
	// Reject private/loopback/link-local IP addresses.
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return errors.New("webhook url must not target private or internal addresses")
		}
	}
	return nil
}
