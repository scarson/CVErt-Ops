// ABOUTME: HTTP handlers for group management: CRUD, soft-delete, and member management.
// ABOUTME: Routes use chi middleware for per-group RBAC enforcement.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// groupEntry is the JSON representation of a group in responses.
type groupEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

// createGroupBody is the request body for POST /groups.
type createGroupBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// updateGroupBody is the request body for PATCH /groups/{id}.
type updateGroupBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// addGroupMemberBody is the request body for POST /groups/{id}/members.
type addGroupMemberBody struct {
	UserID string `json:"user_id"`
}

// groupMemberEntry is one row in the GET /groups/{id}/members response.
type groupMemberEntry struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	JoinedAt    string `json:"joined_at"`
}

// createGroupHandler handles POST /api/v1/orgs/{org_id}/groups.
// Requires admin+.
func (srv *Server) createGroupHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var req createGroupBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	group, err := srv.store.CreateGroup(r.Context(), orgID, req.Name, req.Description)
	if err != nil {
		slog.ErrorContext(r.Context(), "create group", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, groupEntry{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt.Format(time.RFC3339),
	})
}

// listGroupsHandler handles GET /api/v1/orgs/{org_id}/groups.
// Requires viewer+.
func (srv *Server) listGroupsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	rows, err := srv.store.ListOrgGroups(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list groups", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]groupEntry, 0, len(rows))
	for _, g := range rows {
		entries = append(entries, groupEntry{
			ID:          g.ID.String(),
			Name:        g.Name,
			Description: g.Description,
			CreatedAt:   g.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, entries)
}

// getGroupHandler handles GET /api/v1/orgs/{org_id}/groups/{group_id}.
// Requires viewer+.
func (srv *Server) getGroupHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	group, err := srv.store.GetGroup(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get group", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if group == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, groupEntry{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt.Format(time.RFC3339),
	})
}

// updateGroupHandler handles PATCH /api/v1/orgs/{org_id}/groups/{group_id}.
// Requires admin+.
func (srv *Server) updateGroupHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	var req updateGroupBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if err := srv.store.UpdateGroup(r.Context(), orgID, groupID, req.Name, req.Description); err != nil {
		slog.ErrorContext(r.Context(), "update group", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Re-read the group to return the updated state.
	group, err := srv.store.GetGroup(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get group after update", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if group == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, groupEntry{
		ID:          group.ID.String(),
		Name:        group.Name,
		Description: group.Description,
		CreatedAt:   group.CreatedAt.Format(time.RFC3339),
	})
}

// deleteGroupHandler handles DELETE /api/v1/orgs/{org_id}/groups/{group_id}.
// Requires admin+. Performs a soft delete.
func (srv *Server) deleteGroupHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	if err := srv.store.SoftDeleteGroup(r.Context(), orgID, groupID); err != nil {
		slog.ErrorContext(r.Context(), "delete group", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listGroupMembersHandler handles GET /api/v1/orgs/{org_id}/groups/{group_id}/members.
// Requires viewer+.
func (srv *Server) listGroupMembersHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	rows, err := srv.store.ListGroupMembers(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list group members", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]groupMemberEntry, 0, len(rows))
	for _, m := range rows {
		entries = append(entries, groupMemberEntry{
			UserID:      m.UserID.String(),
			Email:       m.Email,
			DisplayName: m.DisplayName,
			JoinedAt:    m.CreatedAt.Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, entries)
}

// addGroupMemberHandler handles POST /api/v1/orgs/{org_id}/groups/{group_id}/members.
// Requires admin+.
func (srv *Server) addGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	var req addGroupMemberBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	if err := srv.store.AddGroupMember(r.Context(), orgID, groupID, userID); err != nil {
		slog.ErrorContext(r.Context(), "add group member", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// removeGroupMemberHandler handles DELETE /api/v1/orgs/{org_id}/groups/{group_id}/members/{user_id}.
// Requires admin+.
func (srv *Server) removeGroupMemberHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "group_id"))
	if err != nil {
		http.Error(w, "invalid group_id", http.StatusBadRequest)
		return
	}

	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	if err := srv.store.RemoveGroupMember(r.Context(), orgID, groupID, userID); err != nil {
		slog.ErrorContext(r.Context(), "remove group member", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
