// ABOUTME: HTTP handlers for org management: create, read, update, members, invitations.
// ABOUTME: Routes use chi middleware (not huma.Register) for per-group RBAC enforcement.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
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

// ── Member management ─────────────────────────────────────────────────────────

// memberEntry is one row in the GET /members response.
type memberEntry struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	JoinedAt    string `json:"joined_at"`
}

// updateMemberRoleBody is the request body for PATCH /members/{user_id}.
type updateMemberRoleBody struct {
	Role string `json:"role"`
}

// updateMemberRoleResponseBody is the response for PATCH /members/{user_id}.
type updateMemberRoleResponseBody struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// listMembersHandler handles GET /api/v1/orgs/{org_id}/members.
// Requires viewer+ (enforced by outer RequireOrgRole middleware).
func (srv *Server) listMembersHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	rows, err := srv.store.ListOrgMembers(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list members", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	members := make([]memberEntry, 0, len(rows))
	for _, m := range rows {
		members = append(members, memberEntry{
			UserID:      m.UserID.String(),
			Email:       m.Email,
			DisplayName: m.DisplayName,
			Role:        m.Role,
			JoinedAt:    m.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, members)
}

// updateMemberRoleHandler handles PATCH /api/v1/orgs/{org_id}/members/{user_id}.
// Requires admin+ (enforced by middleware). Cannot change an existing owner's role
// or assign the owner role (use a transfer-ownership endpoint for that).
func (srv *Server) updateMemberRoleHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	targetIDStr := chi.URLParam(r, "user_id")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	var req updateMemberRoleBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Owner role cannot be assigned via PATCH; use a transfer-ownership endpoint.
	if req.Role == "owner" {
		http.Error(w, "cannot assign owner role via this endpoint", http.StatusBadRequest)
		return
	}
	if req.Role != "admin" && req.Role != "member" && req.Role != "viewer" {
		http.Error(w, "invalid role: must be admin, member, or viewer", http.StatusBadRequest)
		return
	}

	// Caller cannot assign a role higher than their own.
	newRole := parseRole(req.Role)
	if newRole > callerRole {
		http.Error(w, "cannot assign role higher than your own", http.StatusForbidden)
		return
	}

	// Look up the target's current role.
	currentRole, err := srv.store.GetOrgMemberRole(r.Context(), orgID, targetID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get target role", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if currentRole == nil {
		http.Error(w, "user not found in org", http.StatusNotFound)
		return
	}
	if *currentRole == "owner" {
		http.Error(w, "cannot change role of an org owner", http.StatusForbidden)
		return
	}

	if err := srv.store.UpdateOrgMemberRole(r.Context(), orgID, targetID, req.Role); err != nil {
		slog.ErrorContext(r.Context(), "update member role", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, updateMemberRoleResponseBody{
		UserID: targetID.String(),
		Role:   req.Role,
	})
}

// removeMemberHandler handles DELETE /api/v1/orgs/{org_id}/members/{user_id}.
// Requires admin+ (enforced by middleware). Cannot remove the sole owner.
func (srv *Server) removeMemberHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	targetIDStr := chi.URLParam(r, "user_id")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	// Check the target's current role.
	currentRole, err := srv.store.GetOrgMemberRole(r.Context(), orgID, targetID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get target role for remove", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if currentRole == nil {
		http.Error(w, "user not found in org", http.StatusNotFound)
		return
	}

	// Prevent removing the sole owner.
	if *currentRole == "owner" {
		ownerCount, err := srv.store.GetOrgOwnerCount(r.Context(), orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "get owner count", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if ownerCount <= 1 {
			http.Error(w, "cannot remove the sole owner", http.StatusForbidden)
			return
		}
	}

	if err := srv.store.RemoveOrgMember(r.Context(), orgID, targetID); err != nil {
		slog.ErrorContext(r.Context(), "remove member", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── Invitation management ──────────────────────────────────────────────────────

// createInvitationBody is the request body for POST /invitations.
type createInvitationBody struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// invitationEntry is one row in invitation list/create responses.
type invitationEntry struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// createInvitationHandler handles POST /api/v1/orgs/{org_id}/invitations.
// Requires admin+ (enforced by middleware). Always returns 202 — never reveals
// whether the invited email is already registered in the system.
func (srv *Server) createInvitationHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	callerID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req createInvitationBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "admin" && req.Role != "member" && req.Role != "viewer" {
		http.Error(w, "invalid role: must be admin, member, or viewer", http.StatusBadRequest)
		return
	}

	// Caller cannot invite with a role higher than their own effective role.
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if parseRole(req.Role) > callerRole {
		http.Error(w, "cannot invite with role higher than your own", http.StatusForbidden)
		return
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.ErrorContext(r.Context(), "create invitation: generate token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().UTC().Add(7 * 24 * time.Hour)

	inv, err := srv.store.CreateOrgInvitation(r.Context(), orgID, req.Email, req.Role, token, callerID, expiresAt)
	if err != nil {
		slog.ErrorContext(r.Context(), "create invitation", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusAccepted, invitationEntry{
		ID:        inv.ID.String(),
		Email:     inv.Email,
		Role:      inv.Role,
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		CreatedAt: inv.CreatedAt.Format(time.RFC3339),
	})
}

// listInvitationsHandler handles GET /api/v1/orgs/{org_id}/invitations.
// Requires admin+ (enforced by middleware). Returns pending, unexpired invitations.
func (srv *Server) listInvitationsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	rows, err := srv.store.ListOrgInvitations(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list invitations", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]invitationEntry, 0, len(rows))
	for _, inv := range rows {
		entries = append(entries, invitationEntry{
			ID:        inv.ID.String(),
			Email:     inv.Email,
			Role:      inv.Role,
			ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
			CreatedAt: inv.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, entries)
}

// cancelInvitationHandler handles DELETE /api/v1/orgs/{org_id}/invitations/{id}.
// Requires admin+ (enforced by middleware).
func (srv *Server) cancelInvitationHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	idStr := chi.URLParam(r, "id")
	invID, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	if err := srv.store.CancelInvitation(r.Context(), orgID, invID); err != nil {
		slog.ErrorContext(r.Context(), "cancel invitation", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
