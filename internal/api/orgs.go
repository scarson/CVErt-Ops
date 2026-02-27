// ABOUTME: HTTP handlers for org management: create, read, update.
// ABOUTME: Routes use chi middleware (not huma.Register) for per-group RBAC enforcement.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// createOrgBody is the JSON request body for POST /api/v1/orgs.
type createOrgBody struct {
	Name string `json:"name"`
}

// createOrgResponseBody is the JSON response body for POST /api/v1/orgs.
type createOrgResponseBody struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
}

// orgResponseBody is the JSON response body for GET and PATCH /api/v1/orgs/{org_id}.
type orgResponseBody struct {
	OrgID     string `json:"org_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// updateOrgBody is the JSON request body for PATCH /api/v1/orgs/{org_id}.
type updateOrgBody struct {
	Name string `json:"name"`
}

// writeJSON writes v as JSON with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: encode failed", "error", err)
	}
}

// createOrgHandler handles POST /api/v1/orgs.
// Creates a new org and adds the authenticated user as owner.
func (srv *Server) createOrgHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createOrgBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	org, err := srv.store.CreateOrgWithOwner(r.Context(), req.Name, userID)
	if err != nil {
		slog.ErrorContext(r.Context(), "create org", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, createOrgResponseBody{
		OrgID: org.ID.String(),
		Name:  org.Name,
	})
}

// getOrgHandler handles GET /api/v1/orgs/{org_id}.
// Requires at least viewer role (enforced by RequireOrgRole middleware).
func (srv *Server) getOrgHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	org, err := srv.store.GetOrgByID(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get org", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, orgResponseBody{
		OrgID:     org.ID.String(),
		Name:      org.Name,
		CreatedAt: org.CreatedAt.Format(time.RFC3339),
	})
}

// updateOrgHandler handles PATCH /api/v1/orgs/{org_id}.
// Requires at least admin role (enforced by RequireOrgRole middleware).
func (srv *Server) updateOrgHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req updateOrgBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	org, err := srv.store.UpdateOrg(r.Context(), orgID, req.Name)
	if err != nil {
		slog.ErrorContext(r.Context(), "update org", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if org == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, orgResponseBody{
		OrgID:     org.ID.String(),
		Name:      org.Name,
		CreatedAt: org.CreatedAt.Format(time.RFC3339),
	})
}
