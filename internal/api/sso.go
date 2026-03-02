// ABOUTME: HTTP handlers for SSO connection CRUD and email domain management.
// ABOUTME: Enterprise-only, owner-only. Client secrets are encrypted at rest with AES-256-GCM.
package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/tier"
)

// ── Request / response types ────────────────────────────────────────────────

type createSSOBody struct {
	DisplayName  string   `json:"display_name"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Enabled      *bool    `json:"enabled"`
}

type patchSSOBody struct {
	DisplayName  *string  `json:"display_name"`
	IssuerURL    *string  `json:"issuer_url"`
	ClientID     *string  `json:"client_id"`
	ClientSecret *string  `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Enabled      *bool    `json:"enabled"`
}

type ssoResponse struct {
	ID           string   `json:"id"`
	OrgID        string   `json:"org_id"`
	DisplayName  string   `json:"display_name"`
	IssuerURL    string   `json:"issuer_url"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
	Enabled      bool     `json:"enabled"`
	Domains      []string `json:"domains"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

type putSSODomainsBody struct {
	Domains []string `json:"domains"`
}

type discoverBody struct {
	Email string `json:"email"`
}

type discoverResponse struct {
	DisplayName  string `json:"display_name,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
}

// ── Helpers ─────────────────────────────────────────────────────────────────

// ssoEncryptionKey parses the hex-encoded 32-byte SSO encryption key from config.
func (srv *Server) ssoEncryptionKey() ([32]byte, error) {
	var key [32]byte
	raw, err := hex.DecodeString(srv.cfg.SSOEncryptionKey)
	if err != nil {
		return key, fmt.Errorf("SSO_ENCRYPTION_KEY: invalid hex: %w", err)
	}
	if len(raw) != 32 {
		return key, fmt.Errorf("SSO_ENCRYPTION_KEY: need 32 bytes, got %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// requireEnterpriseTier checks that the request is from an enterprise-tier org.
// Returns false (and writes the HTTP error) if gating fails.
func requireEnterpriseTier(w http.ResponseWriter, r *http.Request) bool {
	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		slog.ErrorContext(r.Context(), "sso: tier resolver missing from context")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return false
	}
	if resolver.Tier != "enterprise" {
		http.Error(w, "SSO requires enterprise tier", http.StatusForbidden)
		return false
	}
	return true
}

// ── Handlers ────────────────────────────────────────────────────────────────

// createSSOHandler handles POST /api/v1/orgs/{org_id}/sso.
func (srv *Server) createSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	var req createSSOBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		http.Error(w, "display_name is required", http.StatusUnprocessableEntity)
		return
	}
	if strings.TrimSpace(req.IssuerURL) == "" {
		http.Error(w, "issuer_url is required", http.StatusUnprocessableEntity)
		return
	}
	if strings.TrimSpace(req.ClientID) == "" {
		http.Error(w, "client_id is required", http.StatusUnprocessableEntity)
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		http.Error(w, "client_secret is required", http.StatusUnprocessableEntity)
		return
	}

	// Encrypt client secret at rest.
	key, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(r.Context(), "sso create: encryption key", "error", err)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}
	encSecret, err := crypto.Encrypt(key, []byte(req.ClientSecret))
	if err != nil {
		slog.ErrorContext(r.Context(), "sso create: encrypt secret", "error", err)
		http.Error(w, "encryption error", http.StatusInternalServerError)
		return
	}

	enabled := false
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	row, err := srv.store.CreateSSOConnection(r.Context(), orgID,
		strings.TrimSpace(req.DisplayName),
		strings.TrimSpace(req.IssuerURL),
		strings.TrimSpace(req.ClientID),
		encSecret, req.Scopes, enabled)
	if err != nil {
		if isUniqueViolation(err) {
			http.Error(w, "SSO connection already exists for this org", http.StatusConflict)
			return
		}
		slog.ErrorContext(r.Context(), "sso create: store", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := ssoResponse{
		ID:           row.ID.String(),
		OrgID:        row.OrgID.String(),
		DisplayName:  row.DisplayName,
		IssuerURL:    row.IssuerUrl,
		ClientID:     row.ClientID,
		ClientSecret: "***",
		Scopes:       row.Scopes,
		Enabled:      row.Enabled,
		Domains:      []string{},
		CreatedAt:    row.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    row.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "create",
		EntityType: "sso_connection",
		EntityID:   row.ID.String(),
		EntityName: row.DisplayName,
		Success:    true,
		NewState: map[string]any{
			"display_name":  row.DisplayName,
			"issuer_url":    row.IssuerUrl,
			"client_id":     row.ClientID,
			"client_secret": "[REDACTED]",
			"enabled":       row.Enabled,
		},
	})

	writeJSON(w, http.StatusCreated, resp)
}

// getSSOHandler handles GET /api/v1/orgs/{org_id}/sso.
func (srv *Server) getSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	row, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso get: store", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if row == nil {
		http.Error(w, "no SSO connection", http.StatusNotFound)
		return
	}

	// Fetch associated domains.
	domains, err := srv.store.ListSSOEmailDomains(r.Context(), orgID, row.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso get: list domains", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if domains == nil {
		domains = []string{}
	}

	resp := ssoResponse{
		ID:           row.ID.String(),
		OrgID:        row.OrgID.String(),
		DisplayName:  row.DisplayName,
		IssuerURL:    row.IssuerUrl,
		ClientID:     row.ClientID,
		ClientSecret: "***",
		Scopes:       row.Scopes,
		Enabled:      row.Enabled,
		Domains:      domains,
		CreatedAt:    row.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    row.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	writeJSON(w, http.StatusOK, resp)
}

// patchSSOHandler handles PATCH /api/v1/orgs/{org_id}/sso.
func (srv *Server) patchSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Read current connection.
	current, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso patch: get", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if current == nil {
		http.Error(w, "no SSO connection", http.StatusNotFound)
		return
	}

	var req patchSSOBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Merge patch fields onto current values.
	displayName := current.DisplayName
	if req.DisplayName != nil {
		displayName = strings.TrimSpace(*req.DisplayName)
	}
	issuerURL := current.IssuerUrl
	if req.IssuerURL != nil {
		issuerURL = strings.TrimSpace(*req.IssuerURL)
	}
	clientID := current.ClientID
	if req.ClientID != nil {
		clientID = strings.TrimSpace(*req.ClientID)
	}
	secretEnc := current.ClientSecretEnc
	if req.ClientSecret != nil {
		key, err := srv.ssoEncryptionKey()
		if err != nil {
			slog.ErrorContext(r.Context(), "sso patch: encryption key", "error", err)
			http.Error(w, "server configuration error", http.StatusInternalServerError)
			return
		}
		secretEnc, err = crypto.Encrypt(key, []byte(*req.ClientSecret))
		if err != nil {
			slog.ErrorContext(r.Context(), "sso patch: encrypt secret", "error", err)
			http.Error(w, "encryption error", http.StatusInternalServerError)
			return
		}
	}
	scopes := current.Scopes
	if req.Scopes != nil {
		scopes = req.Scopes
	}
	enabled := current.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	if err := srv.store.UpdateSSOConnection(r.Context(), orgID,
		displayName, issuerURL, clientID, secretEnc, scopes, enabled); err != nil {
		slog.ErrorContext(r.Context(), "sso patch: update", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Evict stale OIDC provider if issuer URL changed.
	if req.IssuerURL != nil && issuerURL != current.IssuerUrl {
		srv.oidcProviders.Delete(current.IssuerUrl)
	}

	// Re-read to get updated timestamps.
	updated, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil || updated == nil {
		slog.ErrorContext(r.Context(), "sso patch: re-read", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	domains, err := srv.store.ListSSOEmailDomains(r.Context(), orgID, updated.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso patch: list domains", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if domains == nil {
		domains = []string{}
	}

	resp := ssoResponse{
		ID:           updated.ID.String(),
		OrgID:        updated.OrgID.String(),
		DisplayName:  updated.DisplayName,
		IssuerURL:    updated.IssuerUrl,
		ClientID:     updated.ClientID,
		ClientSecret: "***",
		Scopes:       updated.Scopes,
		Enabled:      updated.Enabled,
		Domains:      domains,
		CreatedAt:    updated.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    updated.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
	}

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "update",
		EntityType: "sso_connection",
		EntityID:   updated.ID.String(),
		EntityName: updated.DisplayName,
		Success:    true,
		OldState: map[string]any{
			"display_name": current.DisplayName,
			"issuer_url":   current.IssuerUrl,
			"client_id":    current.ClientID,
			"enabled":      current.Enabled,
		},
		NewState: map[string]any{
			"display_name": updated.DisplayName,
			"issuer_url":   updated.IssuerUrl,
			"client_id":    updated.ClientID,
			"enabled":      updated.Enabled,
		},
	})

	writeJSON(w, http.StatusOK, resp)
}

// deleteSSOHandler handles DELETE /api/v1/orgs/{org_id}/sso.
func (srv *Server) deleteSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Read current connection for audit trail before deleting.
	current, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso delete: get", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := srv.store.DeleteSSOConnection(r.Context(), orgID); err != nil {
		slog.ErrorContext(r.Context(), "sso delete: store", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if current != nil {
		srv.oidcProviders.Delete(current.IssuerUrl)
		srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
			OrgID:      orgID,
			Action:     "delete",
			EntityType: "sso_connection",
			EntityID:   current.ID.String(),
			EntityName: current.DisplayName,
			Success:    true,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// putSSODomainsHandler handles PUT /api/v1/orgs/{org_id}/sso/domains.
func (srv *Server) putSSODomainsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Look up the connection for this org.
	conn, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso put domains: get connection", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conn == nil {
		http.Error(w, "no SSO connection", http.StatusNotFound)
		return
	}

	var req putSSODomainsBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Normalize and validate domains (RFC 1035 labels).
	for i := range req.Domains {
		req.Domains[i] = strings.ToLower(strings.TrimSpace(req.Domains[i]))
		d := req.Domains[i]
		if err := validateDomain(d); err != nil {
			http.Error(w, "invalid domain: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	if err := srv.store.SetSSOEmailDomains(r.Context(), conn.ID, orgID, req.Domains); err != nil {
		slog.ErrorContext(r.Context(), "sso put domains: store", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"domains": req.Domains})
}

// validateDomain checks that a domain name conforms to RFC 1035 label rules:
// each label 1–63 chars, alphanumeric + hyphens only, no leading/trailing hyphens,
// total length ≤ 253, at least two labels, ASCII only.
func validateDomain(d string) error {
	if d == "" {
		return fmt.Errorf("empty")
	}
	if len(d) > 253 {
		return fmt.Errorf("%s exceeds 253 characters", d)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%s has no dot", d)
	}
	for _, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%s has empty label", d)
		}
		if len(label) > 63 {
			return fmt.Errorf("%s has label exceeding 63 characters", d)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%s has label with leading/trailing hyphen", d)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("%s contains invalid character %q", d, c)
			}
		}
	}
	return nil
}

// discoverHandler handles POST /api/v1/auth/discover.
// Public endpoint (no auth). Extracts domain from email and looks up SSO connection.
func (srv *Server) discoverHandler(w http.ResponseWriter, r *http.Request) {
	var req discoverBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		http.Error(w, "email is required", http.StatusUnprocessableEntity)
		return
	}

	// Extract domain from email.
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		http.Error(w, "invalid email format", http.StatusUnprocessableEntity)
		return
	}
	domain := strings.ToLower(parts[1])

	row, err := srv.store.LookupSSOByDomain(r.Context(), domain)
	if err != nil {
		slog.ErrorContext(r.Context(), "discover: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if row == nil {
		writeJSON(w, http.StatusOK, discoverResponse{})
		return
	}

	writeJSON(w, http.StatusOK, discoverResponse{
		DisplayName:  row.DisplayName,
		ConnectionID: row.ID.String(),
	})
}
