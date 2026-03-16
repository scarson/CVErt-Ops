// ABOUTME: HTTP handlers for API key management: create, list, revoke.
// ABOUTME: Routes use chi middleware for per-group RBAC enforcement.
package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
)

// createAPIKeyBody is the JSON request body for POST /api/v1/orgs/{org_id}/api-keys.
type createAPIKeyBody struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339; omit for never-expiring key
}

// createAPIKeyResponse is the JSON response body for POST /api/v1/orgs/{org_id}/api-keys.
// raw_key is shown exactly once — it cannot be retrieved again.
type createAPIKeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	RawKey    string `json:"raw_key"`              // shown exactly once; store securely
	ExpiresAt string `json:"expires_at,omitempty"` // RFC3339; omitted when key never expires
	CreatedAt string `json:"created_at"`
}

// apiKeyEntry is one row in the GET /api-keys response.
// Never contains raw_key or key_hash.
type apiKeyEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Role       string `json:"role"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	CreatedAt  string `json:"created_at"`
}

// validAPIKeyRoles are the roles that may be assigned to an API key.
// Owner is excluded — API keys cannot hold owner-level privileges.
var validAPIKeyRoles = map[string]bool{
	"viewer": true,
	"member": true,
	"admin":  true,
}

// createAPIKeyHandler handles POST /api/v1/orgs/{org_id}/api-keys.
// Requires member+. The role in the request body must be ≤ caller's effective role.
// raw_key is returned exactly once in the response.
func (srv *Server) createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req createAPIKeyBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, decErr.Message, decErr)
		return
	}
	if req.Name == "" {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "name is required", Location: "body.name"})
		return
	}
	if !validAPIKeyRoles[req.Role] {
		writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
			&huma.ErrorDetail{Message: "role must be viewer, member, or admin", Location: "body.role"})
		return
	}
	// Enforce role ≤ caller's effective role (no privilege escalation).
	if parseRole(req.Role) > callerRole {
		writeProblem(w, http.StatusForbidden, "forbidden: requested role exceeds your role")
		return
	}

	var expiresAt sql.NullTime
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeProblemWithErrors(w, http.StatusUnprocessableEntity, "validation failed",
				&huma.ErrorDetail{Message: "invalid expires_at: use RFC3339 format", Location: "body.expires_at"})
			return
		}
		expiresAt = sql.NullTime{Time: t, Valid: true}
	}

	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		slog.ErrorContext(r.Context(), "generate api key", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	key, err := srv.store.CreateAPIKey(r.Context(), orgID, callerID, keyHash, req.Name, req.Role, expiresAt)
	if err != nil {
		slog.ErrorContext(r.Context(), "create api key", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	out := createAPIKeyResponse{
		ID:        key.ID.String(),
		Name:      key.Name,
		Role:      key.Role,
		RawKey:    rawKey,
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
	}
	if key.ExpiresAt.Valid {
		out.ExpiresAt = key.ExpiresAt.Time.Format(time.RFC3339)
	}

	writeLocation(w, r, key.ID.String())
	writeJSON(w, http.StatusCreated, out)
}

// listAPIKeysHandler handles GET /api/v1/orgs/{org_id}/api-keys.
// Requires viewer+. Never returns key_hash or raw_key.
func (srv *Server) listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	rows, err := srv.store.ListOrgAPIKeys(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list api keys", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	entries := make([]apiKeyEntry, 0, len(rows))
	for _, k := range rows {
		entry := apiKeyEntry{
			ID:        k.ID.String(),
			Name:      k.Name,
			Role:      k.Role,
			CreatedAt: k.CreatedAt.Format(time.RFC3339),
		}
		if k.ExpiresAt.Valid {
			entry.ExpiresAt = k.ExpiresAt.Time.Format(time.RFC3339)
		}
		if k.LastUsedAt.Valid {
			entry.LastUsedAt = k.LastUsedAt.Time.Format(time.RFC3339)
		}
		if k.RevokedAt.Valid {
			entry.RevokedAt = k.RevokedAt.Time.Format(time.RFC3339)
		}
		entries = append(entries, entry)
	}
	writeList(w, entries, "")
}

// revokeAPIKeyHandler handles DELETE /api/v1/orgs/{org_id}/api-keys/{id}.
// Members may revoke their own keys. Admin+ may revoke any key.
func (srv *Server) revokeAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	keyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid id")
		return
	}

	// Admin+ can revoke any key; members/viewers can only revoke their own.
	if callerRole < RoleAdmin {
		key, err := srv.store.GetOrgAPIKey(r.Context(), orgID, keyID)
		if err != nil {
			slog.ErrorContext(r.Context(), "get api key for revoke", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		if key == nil {
			writeProblem(w, http.StatusNotFound, "not found")
			return
		}
		if key.CreatedByUserID != callerID {
			writeProblem(w, http.StatusForbidden, "forbidden")
			return
		}
	}

	if err := srv.store.RevokeAPIKey(r.Context(), orgID, keyID); err != nil {
		slog.ErrorContext(r.Context(), "revoke api key", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
