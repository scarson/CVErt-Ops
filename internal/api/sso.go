// ABOUTME: HTTP handlers for SSO connection CRUD and email domain management.
// ABOUTME: Enterprise-only, owner-only. Client secrets are encrypted at rest with AES-256-GCM.
package api

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
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
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return false
	}
	if resolver.Tier != "enterprise" {
		writeProblemTyped(w, http.StatusForbidden, problemTypeTierLimit, "SSO requires enterprise tier")
		return false
	}
	return true
}

// ── Handlers ────────────────────────────────────────────────────────────────

// createSSOHandler handles POST /api/v1/orgs/{org_id}/sso.
func (srv *Server) createSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	var req createSSOBody
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "display_name is required", Location: "body.display_name"})
		return
	}
	if strings.TrimSpace(req.IssuerURL) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "issuer_url is required", Location: "body.issuer_url"})
		return
	}
	if strings.TrimSpace(req.ClientID) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "client_id is required", Location: "body.client_id"})
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "client_secret is required", Location: "body.client_secret"})
		return
	}

	// Encrypt client secret at rest.
	key, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(r.Context(), "sso create: encryption key", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server configuration error")
		return
	}
	encSecret, err := crypto.Encrypt(key, []byte(req.ClientSecret))
	if err != nil {
		slog.ErrorContext(r.Context(), "sso create: encrypt secret", "error", err)
		writeProblem(w, http.StatusInternalServerError, "encryption error")
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
			writeProblem(w, http.StatusConflict, "SSO connection already exists for this org")
			return
		}
		slog.ErrorContext(r.Context(), "sso create: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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

	writeLocation(w, r, row.ID.String())
	writeJSON(w, http.StatusCreated, resp)
}

// getSSOHandler handles GET /api/v1/orgs/{org_id}/sso.
func (srv *Server) getSSOHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	row, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso get: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "no SSO connection")
		return
	}

	// Fetch associated domains.
	domains, err := srv.store.ListSSOEmailDomains(r.Context(), orgID, row.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso get: list domains", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Read current connection.
	current, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso patch: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "no SSO connection")
		return
	}

	var req patchSSOBody
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	// Merge patch fields onto current values, rejecting empty-after-trim values.
	displayName := current.DisplayName
	if req.DisplayName != nil {
		displayName = strings.TrimSpace(*req.DisplayName)
		if displayName == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "display_name cannot be empty", Location: "body.display_name"})
			return
		}
	}
	issuerURL := current.IssuerUrl
	if req.IssuerURL != nil {
		issuerURL = strings.TrimSpace(*req.IssuerURL)
		if issuerURL == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "issuer_url cannot be empty", Location: "body.issuer_url"})
			return
		}
	}
	clientID := current.ClientID
	if req.ClientID != nil {
		clientID = strings.TrimSpace(*req.ClientID)
		if clientID == "" {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "client_id cannot be empty", Location: "body.client_id"})
			return
		}
	}
	secretEnc := current.ClientSecretEnc
	if req.ClientSecret != nil {
		key, err := srv.ssoEncryptionKey()
		if err != nil {
			slog.ErrorContext(r.Context(), "sso patch: encryption key", "error", err)
			writeProblem(w, http.StatusInternalServerError, "server configuration error")
			return
		}
		secretEnc, err = crypto.Encrypt(key, []byte(*req.ClientSecret))
		if err != nil {
			slog.ErrorContext(r.Context(), "sso patch: encrypt secret", "error", err)
			writeProblem(w, http.StatusInternalServerError, "encryption error")
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
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	domains, err := srv.store.ListSSOEmailDomains(r.Context(), orgID, updated.ID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso patch: list domains", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Read current connection for audit trail before deleting.
	current, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso delete: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "no SSO connection")
		return
	}

	if err := srv.store.DeleteSSOConnection(r.Context(), orgID); err != nil {
		slog.ErrorContext(r.Context(), "sso delete: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.oidcProviders.Delete(current.IssuerUrl)
	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "sso_connection",
		EntityID:   current.ID.String(),
		EntityName: current.DisplayName,
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

// putSSODomainsHandler handles PUT /api/v1/orgs/{org_id}/sso/domains.
func (srv *Server) putSSODomainsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Look up the connection for this org.
	conn, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "sso put domains: get connection", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if conn == nil {
		writeProblem(w, http.StatusNotFound, "no SSO connection")
		return
	}

	var req putSSODomainsBody
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	// Normalize and validate domains (RFC 1035 labels).
	for i := range req.Domains {
		req.Domains[i] = strings.ToLower(strings.TrimSpace(req.Domains[i]))
		d := req.Domains[i]
		if err := validateDomain(d); err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "invalid domain: " + err.Error(), Location: "body.domains", Value: d})
			return
		}
	}

	if err := srv.store.SetSSOEmailDomains(r.Context(), conn.ID, orgID, req.Domains); err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "domain already claimed by another organization")
			return
		}
		slog.ErrorContext(r.Context(), "sso put domains: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "update_domains",
		EntityType: "sso_connection",
		EntityID:   conn.ID.String(),
		EntityName: conn.DisplayName,
		Success:    true,
	})

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
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "email is required", Location: "body.email"})
		return
	}

	// Extract domain from email.
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "invalid email format", Location: "body.email", Value: email})
		return
	}
	domain := strings.ToLower(parts[1])

	row, err := srv.store.LookupSSOByDomain(r.Context(), domain)
	if err != nil {
		slog.ErrorContext(r.Context(), "discover: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
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
