// ABOUTME: HTTP handlers for notification channel CRUD and signing secret rotation.
// ABOUTME: signing_secret is returned only on create and rotate-secret responses — never on GET/LIST/PATCH.
package api

import (
	"bytes"
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

	"github.com/danielgtaylor/huma/v2"
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
	Name   *string          `json:"name,omitempty"`
	Config *json.RawMessage `json:"config,omitempty" doc:"Replaces the whole config. Masked values read from this API may be sent back to keep the stored secret while the webhook scheme and host are unchanged. A changed scheme or host needs each secret sent again."`
}

// ChannelEntry is the API shape of a notification channel. It is exported so
// huma documents its fields where channelCreateEntry embeds it.
type ChannelEntry struct {
	ID        string          `json:"id"`
	OrgID     string          `json:"org_id"`
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Config    json.RawMessage `json:"config" doc:"Secrets are masked for every role. custom_headers keeps header names with each value replaced by [REDACTED]; url is reduced to scheme://host/***. The value of any field delivery does not read is replaced by [REDACTED]."`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

// channelCreateEntry extends ChannelEntry with the signing secret, returned only at creation.
type channelCreateEntry struct {
	ChannelEntry
	SigningSecret string `json:"signing_secret,omitempty" doc:"Webhook channels only. Shown once, at creation."`
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	var req createChannelBody
	if !decodeJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "name is required", Location: "body.name"})
		return
	}
	if req.Type == "" {
		req.Type = "webhook"
	}
	if req.Type != "webhook" && req.Type != "email" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "type must be 'webhook' or 'email'", Location: "body.type"})
		return
	}

	// Tier gating: check channel type availability.
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "tier resolver missing from context")
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
		writeProblemTyped(w, http.StatusForbidden, problemTypeTierLimit, "channel type not available for current tier")
		return
	}

	resolved, resolveErr := resolveMaskedChannelConfig(req.Config, nil)
	if resolveErr != nil {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: resolveErr.Error(), Location: "body.config"})
		return
	}
	req.Config = resolved

	// For webhook channels, validate that config contains a non-empty, SSRF-safe url.
	if req.Type == "webhook" {
		var cfg map[string]any
		if err := json.Unmarshal(req.Config, &cfg); err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "webhook config must be valid JSON with a url field", Location: "body.config"})
			return
		}
		urlVal, ok := cfg["url"].(string)
		if !ok || strings.TrimSpace(urlVal) == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "webhook config must include a non-empty url", Location: "body.config.url"})
			return
		}
		if err := validateWebhookURL(urlVal, srv.privateDests); err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: err.Error(), Location: "body.config.url"})
			return
		}
	}

	if req.Type == "email" {
		if _, err := validateEmailConfig(req.Config); err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: err.Error(), Location: "body.config.recipients"})
			return
		}
	}

	row, secret, err := srv.store.CreateNotificationChannel(r.Context(), orgID, req.Name, req.Type, req.Config)
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "a channel with this name already exists")
			return
		}
		slog.ErrorContext(r.Context(), "create notification channel", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	entry := ChannelEntry{
		ID:        row.ID.String(),
		OrgID:     row.OrgID.String(),
		Name:      row.Name,
		Type:      row.Type,
		Config:    channelResponseConfig(row.Config),
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	}
	writeLocation(w, r, row.ID.String())
	if req.Type == "webhook" {
		writeJSON(w, http.StatusCreated, channelCreateEntry{
			ChannelEntry:  entry,
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}
	row, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, ChannelEntry{
		ID:        row.ID.String(),
		OrgID:     row.OrgID.String(),
		Name:      row.Name,
		Type:      row.Type,
		Config:    channelResponseConfig(row.Config),
		CreatedAt: row.CreatedAt.Format(time.RFC3339),
		UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
	})
}

// listChannelsHandler handles GET /api/v1/orgs/{org_id}/channels.
func (srv *Server) listChannelsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	rows, err := srv.store.ListNotificationChannels(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list notification channels", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	items := make([]ChannelEntry, len(rows))
	for i, row := range rows {
		items[i] = ChannelEntry{
			ID:        row.ID.String(),
			OrgID:     row.OrgID.String(),
			Name:      row.Name,
			Type:      row.Type,
			Config:    channelResponseConfig(row.Config),
			CreatedAt: row.CreatedAt.Format(time.RFC3339),
			UpdatedAt: row.UpdatedAt.Format(time.RFC3339),
		}
	}
	writeList(w, items, "")
}

// patchChannelHandler handles PATCH /api/v1/orgs/{org_id}/channels/{id}.
// Only supplied fields are updated; absent fields preserve existing values.
func (srv *Server) patchChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	var req patchChannelBody
	if !decodeJSON(w, r, &req) {
		return
	}

	// Fetch current row to preserve unpatched fields.
	current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get notification channel for patch", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	oldState := channelAuditState(current.Name, current.Type, current.Config)

	params := store.UpdateNotificationChannelParams{
		Name:   current.Name,
		Config: current.Config,
	}
	if req.Name != nil {
		if strings.TrimSpace(*req.Name) == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "name cannot be empty", Location: "body.name"})
			return
		}
		params.Name = *req.Name
	}
	if req.Config != nil {
		resolved, resolveErr := resolveMaskedChannelConfig(*req.Config, current.Config)
		if resolveErr != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: resolveErr.Error(), Location: "body.config"})
			return
		}
		req.Config = &resolved
		// Re-validate config when updated.
		if current.Type == "webhook" {
			var cfg map[string]any
			if err := json.Unmarshal(*req.Config, &cfg); err != nil {
				writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "webhook config must be valid JSON with a url field", Location: "body.config"})
				return
			}
			urlVal, ok := cfg["url"].(string)
			if !ok || strings.TrimSpace(urlVal) == "" {
				writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: "webhook config must include a non-empty url", Location: "body.config.url"})
				return
			}
			if err := validateWebhookURL(urlVal, srv.privateDests); err != nil {
				writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: err.Error(), Location: "body.config.url"})
				return
			}
		}
		if current.Type == "email" {
			if _, err := validateEmailConfig(*req.Config); err != nil {
				writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed", &huma.ErrorDetail{Message: err.Error(), Location: "body.config.recipients"})
				return
			}
		}
		params.Config = *req.Config
	}

	updated, err := srv.store.UpdateNotificationChannel(r.Context(), orgID, id, params)
	if err != nil {
		slog.ErrorContext(r.Context(), "update notification channel", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if updated == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, ChannelEntry{
		ID:        updated.ID.String(),
		OrgID:     updated.OrgID.String(),
		Name:      updated.Name,
		Type:      updated.Type,
		Config:    channelResponseConfig(updated.Config),
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Fetch before delete for audit log.
	current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for delete", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	hasBindings, err := srv.store.ChannelHasActiveBindings(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "check channel active bindings", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if hasBindings {
		writeProblem(w, http.StatusConflict, "channel has active bound rules or reports")
		return
	}

	if err := srv.store.SoftDeleteNotificationChannel(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "soft delete notification channel", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for rotate", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ch == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	if ch.Type != "webhook" {
		writeProblem(w, http.StatusUnprocessableEntity, "signing secret operations are only available for webhook channels")
		return
	}

	secret, err := srv.store.RotateSigningSecret(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "rotate signing secret", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if secret == "" {
		// Channel was deleted between GET and rotate (TOCTOU).
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, rotateSecretResponse{SigningSecret: secret})
}

// clearSecondarySecretHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/clear-secondary.
// Clears the secondary signing secret once all consumers have migrated to the new primary.
func (srv *Server) clearSecondarySecretHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for clear-secondary", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ch == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}
	if ch.Type != "webhook" {
		writeProblem(w, http.StatusUnprocessableEntity, "signing secret operations are only available for webhook channels")
		return
	}

	if err := srv.store.ClearSecondarySecret(r.Context(), orgID, id); err != nil {
		slog.ErrorContext(r.Context(), "clear secondary secret", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type testChannelResult struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// testChannelHandler handles POST /api/v1/orgs/{org_id}/channels/{id}/test.
// Sends a test notification through the channel and reports success/failure.
// Always returns 200; delivery outcome is in the response body.
func (srv *Server) testChannelHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Verify channel exists and belongs to this org.
	ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
	if err != nil {
		slog.ErrorContext(r.Context(), "get channel for test", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ch == nil {
		writeProblem(w, http.StatusNotFound, "not found")
		return
	}

	var testErr error
	switch ch.Type {
	case "webhook":
		testErr = srv.testWebhookChannel(r.Context(), id)
	case "email":
		testErr = srv.testEmailChannel(r.Context(), ch.Config)
	default:
		writeProblem(w, http.StatusUnprocessableEntity, "unsupported channel type")
		return
	}

	resp := testChannelResult{Success: testErr == nil}
	status := http.StatusOK
	if testErr != nil {
		resp.Error = testErr.Error()
		status = http.StatusBadGateway
	}
	writeJSON(w, status, resp)
}

func (srv *Server) testWebhookChannel(ctx context.Context, channelID uuid.UUID) error {
	delivery, err := srv.store.GetNotificationChannelForDelivery(ctx, channelID)
	if err != nil {
		return fmt.Errorf("load channel: %w", err)
	}
	if delivery == nil {
		return errors.New("channel not found")
	}

	client, err := notify.BuildSafeClient(srv.privateDests)
	if err != nil {
		return fmt.Errorf("build webhook client: %w", err)
	}

	payload, _ := json.Marshal(map[string]any{
		"test":      true,
		"message":   "Test notification from CVErt Ops",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	// The full error can carry the resolved address (from the SSRF dial check
	// or DNS), which would let an org admin map internal DNS by testing host
	// names, so the caller gets only what org members may read.
	if err := notify.Send(ctx, client, notify.ChannelWebhookConfig(delivery), payload); err != nil {
		slog.WarnContext(ctx, "channel test webhook failed", "channel_id", channelID, "error", err)
		return notify.ErrorForOrg(err)
	}
	return nil
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

// channelResponseConfig returns the config every API caller reads: secrets are
// masked for all roles, as the signing secret is. A stored value that is not a
// JSON object cannot be masked by key, so it is withheld.
func channelResponseConfig(stored json.RawMessage) json.RawMessage {
	var cfg map[string]any
	if err := json.Unmarshal(stored, &cfg); err != nil || cfg == nil {
		return json.RawMessage(`{}`)
	}
	masked, err := json.Marshal(audit.RedactChannelConfig(cfg))
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return masked
}

// resolveMaskedChannelConfig returns a submitted config with masked values
// replaced by the stored secrets they stand for, so a client can send back what
// it read. Pass a nil stored config when there is no existing channel. A stored
// secret stays with its scheme and host: moving a channel elsewhere needs the
// secret sent again, or a caller could direct it to a host they control. Config
// that is not a JSON object is returned as submitted for validation to reject.
func resolveMaskedChannelConfig(submitted, stored json.RawMessage) (json.RawMessage, error) {
	sub := decodeConfigObject(submitted)
	if sub == nil {
		return submitted, nil
	}
	// A missing or unreadable stored config leaves no secrets to restore, and
	// the caller can still replace it with a complete config.
	cur := decodeConfigObject(stored)

	subURL, _ := sub["url"].(string)
	curURL, _ := cur["url"].(string)
	sameDestination := audit.RedactURL(subURL) == audit.RedactURL(curURL)
	switch {
	case curURL != "" && subURL == audit.RedactURL(curURL):
		sub["url"] = curURL
	case subURL != "" && subURL == audit.RedactURL(subURL):
		return nil, errors.New("webhook url is masked; send the full url")
	}

	if err := restoreMaskedValues(sub, cur, sameDestination); err != nil {
		return nil, err
	}
	return json.Marshal(sub)
}

// decodeConfigObject decodes a JSON object with its numbers kept exact, so a
// restored value is stored unchanged. It returns nil if raw is not an object.
func decodeConfigObject(raw json.RawMessage) map[string]any {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil {
		return nil
	}
	return object
}

// restoreMaskedValues replaces each masked value in submitted with the value at
// the same key in stored, following nested objects such as header maps. A masked
// value inside a list has no key to restore from, so it is rejected.
func restoreMaskedValues(submitted, stored map[string]any, sameDestination bool) error {
	for key, value := range submitted {
		switch v := value.(type) {
		case string:
			if v != audit.RedactedValue {
				continue
			}
			storedValue, ok := stored[key]
			if !ok {
				return fmt.Errorf("%q has a masked value and no stored value; send the real value", key)
			}
			if !sameDestination {
				return fmt.Errorf("%q must be sent again when the webhook scheme or host changes", key)
			}
			submitted[key] = storedValue
		case map[string]any:
			nested, _ := stored[key].(map[string]any)
			if err := restoreMaskedValues(v, nested, sameDestination); err != nil {
				return err
			}
		case []any:
			if containsMaskedValue(v) {
				return fmt.Errorf("%q has a masked value inside a list; send the real value", key)
			}
		}
	}
	return nil
}

// containsMaskedValue reports whether value holds the masked placeholder at any depth.
func containsMaskedValue(value any) bool {
	switch v := value.(type) {
	case string:
		return v == audit.RedactedValue
	case []any:
		for _, element := range v {
			if containsMaskedValue(element) {
				return true
			}
		}
	case map[string]any:
		for _, element := range v {
			if containsMaskedValue(element) {
				return true
			}
		}
	}
	return false
}

// channelAuditState builds a flat map for audit log state, merging the masked
// config fields at the top level. The channel's own name and type take
// precedence over config keys of the same name.
func channelAuditState(name, chType string, config json.RawMessage) map[string]any {
	state := map[string]any{}
	var cfgMap map[string]any
	if err := json.Unmarshal(config, &cfgMap); err == nil {
		for k, v := range audit.RedactChannelConfig(cfgMap) {
			state[k] = v
		}
	}
	state["name"] = name
	state["type"] = chType
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
func validateWebhookURL(rawURL string, private notify.PrivateDestinations) error {
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
	// Hosts the operator listed in WEBHOOK_PRIVATE_HOSTS may be private. The
	// delivery client still confines them to WEBHOOK_PRIVATE_CIDRS.
	if private.Allows(host) {
		return nil
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
