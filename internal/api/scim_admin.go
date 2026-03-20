// ABOUTME: HTTP handlers for SCIM config admin CRUD (create, read, update, delete, token rotation).
// ABOUTME: Standard auth (cookie-based), RFC 9457 errors. Enterprise-tier-gated. Owner-only for mutations.
package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/secure"
)

// ── Request / response types ────────────────────────────────────────────────

type scimConfigResponse struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	Enabled     bool   `json:"enabled"`
	DefaultRole string `json:"default_role"`
	TokenPrefix string `json:"token_prefix"`
	Token       string `json:"token,omitempty"` // only set on create and rotate
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

type patchSCIMConfigBody struct {
	Enabled     *bool   `json:"enabled"`
	DefaultRole *string `json:"default_role"`
}

type rotateTokenResponse struct {
	Token       string `json:"token"`
	TokenPrefix string `json:"token_prefix"`
}

type scimGroupItem struct {
	ID            string  `json:"id"`
	ExternalID    *string `json:"external_id"`
	DisplayName   string  `json:"display_name"`
	MappedRole    *string `json:"mapped_role"`
	MappedGroupID *string `json:"mapped_group_id"`
	MemberCount   int     `json:"member_count"`
	CreatedAt     string  `json:"created_at"`
}

type listSCIMGroupsResponse struct {
	Items []scimGroupItem `json:"items"`
}

type patchSCIMGroupMappingBody struct {
	MappedRole    *string    `json:"mapped_role"`
	MappedGroupID *uuid.UUID `json:"mapped_group_id"`
}

type scimGroupResponse struct {
	ID            string  `json:"id"`
	ExternalID    *string `json:"external_id"`
	DisplayName   string  `json:"display_name"`
	MappedRole    *string `json:"mapped_role"`
	MappedGroupID *string `json:"mapped_group_id"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// ── Handlers ────────────────────────────────────────────────────────────────

// createSCIMConfigHandler handles POST /api/v1/orgs/{org_id}/sso/scim.
func (srv *Server) createSCIMConfigHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Verify SSO connection exists for this org.
	ssoConn, err := srv.store.GetSSOConnection(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim config create: get sso connection", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if ssoConn == nil {
		writeProblem(w, http.StatusBadRequest, "SSO connection required before enabling SCIM")
		return
	}

	// Generate bearer token.
	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		slog.ErrorContext(r.Context(), "scim config create: generate token", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	row, err := srv.store.CreateSCIMConfig(r.Context(), orgID, ssoConn.ID, false, tokenHash, tokenPrefix, "viewer")
	if err != nil {
		if isUniqueViolation(err) {
			writeProblem(w, http.StatusConflict, "SCIM configuration already exists for this organization")
			return
		}
		slog.ErrorContext(r.Context(), "scim config create: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.fireSCIMEvent(r.Context(), secure.EventSCIMTokenCreated, &orgID)

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "create",
		EntityType: "scim_config",
		EntityID:   row.ID.String(),
		Success:    true,
		NewState: map[string]any{
			"enabled":      false,
			"default_role": "viewer",
		},
	})

	writeJSON(w, http.StatusCreated, scimConfigResponse{
		ID:          row.ID.String(),
		OrgID:       row.OrgID.String(),
		Enabled:     row.Enabled,
		DefaultRole: row.DefaultRole,
		TokenPrefix: row.TokenPrefix,
		Token:       rawToken,
		CreatedAt:   row.CreatedAt.Format(time.RFC3339),
	})
}

// getSCIMConfigHandler handles GET /api/v1/orgs/{org_id}/sso/scim.
func (srv *Server) getSCIMConfigHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	row, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim config get: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if row == nil {
		writeProblem(w, http.StatusNotFound, "no SCIM configuration")
		return
	}

	writeJSON(w, http.StatusOK, scimConfigResponse{
		ID:          row.ID.String(),
		OrgID:       row.OrgID.String(),
		Enabled:     row.Enabled,
		DefaultRole: row.DefaultRole,
		TokenPrefix: row.TokenPrefix,
		CreatedAt:   row.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   row.UpdatedAt.Format(time.RFC3339),
	})
}

// patchSCIMConfigHandler handles PATCH /api/v1/orgs/{org_id}/sso/scim.
func (srv *Server) patchSCIMConfigHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	current, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim config patch: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if current == nil {
		writeProblem(w, http.StatusNotFound, "no SCIM configuration")
		return
	}

	var req patchSCIMConfigBody
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	enabled := current.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	defaultRole := current.DefaultRole
	if req.DefaultRole != nil {
		role := strings.TrimSpace(*req.DefaultRole)
		if role != "viewer" && role != "member" {
			writeProblem(w, http.StatusBadRequest, "default_role must be 'viewer' or 'member'")
			return
		}
		defaultRole = role
	}

	if err := srv.store.UpdateSCIMConfig(r.Context(), orgID, enabled, defaultRole); err != nil {
		slog.ErrorContext(r.Context(), "scim config patch: update", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Re-read to get updated timestamps.
	updated, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil || updated == nil {
		slog.ErrorContext(r.Context(), "scim config patch: re-read", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "update",
		EntityType: "scim_config",
		EntityID:   updated.ID.String(),
		Success:    true,
		OldState: map[string]any{
			"enabled":      current.Enabled,
			"default_role": current.DefaultRole,
		},
		NewState: map[string]any{
			"enabled":      updated.Enabled,
			"default_role": updated.DefaultRole,
		},
	})

	writeJSON(w, http.StatusOK, scimConfigResponse{
		ID:          updated.ID.String(),
		OrgID:       updated.OrgID.String(),
		Enabled:     updated.Enabled,
		DefaultRole: updated.DefaultRole,
		TokenPrefix: updated.TokenPrefix,
		CreatedAt:   updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   updated.UpdatedAt.Format(time.RFC3339),
	})
}

// deleteSCIMConfigHandler handles DELETE /api/v1/orgs/{org_id}/sso/scim.
func (srv *Server) deleteSCIMConfigHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Read current for audit trail.
	current, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim config delete: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Idempotent: 204 even if no config exists.
	if current != nil {
		if err := srv.store.DeleteSCIMConfig(r.Context(), orgID); err != nil {
			slog.ErrorContext(r.Context(), "scim config delete: store", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}

		srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
			OrgID:      orgID,
			Action:     "delete",
			EntityType: "scim_config",
			EntityID:   current.ID.String(),
			Success:    true,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// rotateSCIMTokenHandler handles POST /api/v1/orgs/{org_id}/sso/scim/rotate-token.
func (srv *Server) rotateSCIMTokenHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	// Verify config exists.
	cfg, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim token rotate: get", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if cfg == nil {
		writeProblem(w, http.StatusNotFound, "no SCIM configuration")
		return
	}

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		slog.ErrorContext(r.Context(), "scim token rotate: generate", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := srv.store.RotateSCIMToken(r.Context(), orgID, tokenHash, tokenPrefix); err != nil {
		slog.ErrorContext(r.Context(), "scim token rotate: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	srv.fireSCIMEvent(r.Context(), secure.EventSCIMTokenRotated, &orgID)

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "update",
		EntityType: "scim_config",
		EntityID:   cfg.ID.String(),
		Success:    true,
	})

	writeJSON(w, http.StatusOK, rotateTokenResponse{
		Token:       rawToken,
		TokenPrefix: tokenPrefix,
	})
}

// listSCIMGroupsHandler handles GET /api/v1/orgs/{org_id}/sso/scim/groups.
func (srv *Server) listSCIMGroupsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	rows, err := srv.store.ListSCIMGroups(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim groups list: store", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	items := make([]scimGroupItem, 0, len(rows))
	for _, g := range rows {
		item := scimGroupItem{
			ID:          g.ID.String(),
			DisplayName: g.DisplayName,
			MemberCount: int(g.MemberCount),
			CreatedAt:   g.CreatedAt.Format(time.RFC3339),
		}
		if g.ExternalID.Valid {
			item.ExternalID = &g.ExternalID.String
		}
		if g.MappedRole.Valid {
			item.MappedRole = &g.MappedRole.String
		}
		if g.MappedGroupID.Valid {
			s := g.MappedGroupID.UUID.String()
			item.MappedGroupID = &s
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, listSCIMGroupsResponse{Items: items})
}

// patchSCIMGroupMappingHandler handles PATCH /api/v1/orgs/{org_id}/sso/scim/groups/{id}/mapping.
func (srv *Server) patchSCIMGroupMappingHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	if !requireEnterpriseTier(w, r) {
		return
	}

	groupID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid group id")
		return
	}

	// Get the SCIM group and verify it belongs to this org.
	scimGroup, err := srv.store.GetSCIMGroup(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim group mapping patch: get group", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if scimGroup == nil {
		writeProblem(w, http.StatusNotFound, "SCIM group not found")
		return
	}

	var req patchSCIMGroupMappingBody
	if errDetail := decodeJSON(r, &req); errDetail != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", errDetail)
		return
	}

	// Track whether each field was sent in the request (even if to clear).
	roleSent := req.MappedRole != nil
	groupIDSent := req.MappedGroupID != nil

	// Validate mapped_role if provided.
	if roleSent {
		role := strings.TrimSpace(*req.MappedRole)
		if role != "" && role != "viewer" && role != "member" && role != "admin" {
			writeProblem(w, http.StatusBadRequest, "mapped_role must be 'viewer', 'member', or 'admin'")
			return
		}
		if role == "" {
			req.MappedRole = nil // clear the mapping
		} else {
			req.MappedRole = &role
		}
	}

	// Validate mapped_group_id if provided: must be same org and active.
	if groupIDSent {
		group, err := srv.store.GetGroupIfActive(r.Context(), *req.MappedGroupID)
		if err != nil {
			slog.ErrorContext(r.Context(), "scim group mapping patch: get notification group", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		if group == nil {
			writeProblem(w, http.StatusBadRequest, "notification group not found or deleted")
			return
		}
		if group.OrgID != orgID {
			writeProblem(w, http.StatusBadRequest, "notification group belongs to a different organization")
			return
		}
	}

	// Capture old mapping for comparison.
	oldMappedRole := scimGroup.MappedRole
	oldMappedGroupID := scimGroup.MappedGroupID

	// Build the final values: use new value if sent, else keep current.
	// req.MappedRole == nil after validation means "clear" if roleSent is true.
	var mappedRolePtr *string
	if roleSent {
		mappedRolePtr = req.MappedRole // nil means clear, non-nil means set
	} else if scimGroup.MappedRole.Valid {
		mappedRolePtr = &scimGroup.MappedRole.String
	}

	var mappedGroupIDPtr *uuid.UUID
	if groupIDSent {
		mappedGroupIDPtr = req.MappedGroupID
	} else if scimGroup.MappedGroupID.Valid {
		mappedGroupIDPtr = &scimGroup.MappedGroupID.UUID
	}

	if err := srv.store.UpdateSCIMGroupMapping(r.Context(), orgID, groupID, mappedRolePtr, mappedGroupIDPtr); err != nil {
		slog.ErrorContext(r.Context(), "scim group mapping patch: update", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Get SCIM config for default role (needed for role recomputation).
	scimCfg, err := srv.store.GetSCIMConfig(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim group mapping patch: get scim config", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	defaultRole := "viewer"
	if scimCfg != nil {
		defaultRole = scimCfg.DefaultRole
	}

	// Apply immediate effects to all current members.
	members, err := srv.store.ListSCIMGroupMembers(r.Context(), orgID, groupID)
	if err != nil {
		slog.ErrorContext(r.Context(), "scim group mapping patch: list members", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	roleChanged := roleSent && ptrStringDiffers(mappedRolePtr, oldMappedRole)
	groupIDChanged := groupIDSent && ptrUUIDDiffers(mappedGroupIDPtr, oldMappedGroupID)

	for _, userID := range members {
		// Role recomputation (if mapped_role changed).
		if roleChanged {
			if err := srv.recomputeSCIMRole(r.Context(), orgID, userID, defaultRole); err != nil {
				slog.ErrorContext(r.Context(), "scim group mapping: role recomputation failed",
					"user_id", userID, "error", err)
			}
		}

		// Notification group sync (if mapped_group_id changed).
		if groupIDChanged {
			// Remove from old notification group if applicable.
			if oldMappedGroupID.Valid {
				if err := srv.syncNotifGroupRemove(r.Context(), orgID, userID, oldMappedGroupID.UUID, groupID); err != nil {
					slog.ErrorContext(r.Context(), "scim group mapping: notification group remove failed",
						"user_id", userID, "error", err)
				}
			}
			// Add to new notification group if applicable.
			if mappedGroupIDPtr != nil {
				if err := srv.syncNotifGroupAdd(r.Context(), orgID, userID, *mappedGroupIDPtr, groupID); err != nil {
					slog.ErrorContext(r.Context(), "scim group mapping: notification group add failed",
						"user_id", userID, "error", err)
				}
			}
		}
	}

	srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
		OrgID:      orgID,
		Action:     "update",
		EntityType: "scim_group",
		EntityID:   groupID.String(),
		EntityName: scimGroup.DisplayName,
		Success:    true,
	})

	// Re-read the group to get updated state.
	updated, err := srv.store.GetSCIMGroup(r.Context(), orgID, groupID)
	if err != nil || updated == nil {
		slog.ErrorContext(r.Context(), "scim group mapping patch: re-read", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	resp := scimGroupResponse{
		ID:          updated.ID.String(),
		DisplayName: updated.DisplayName,
		CreatedAt:   updated.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   updated.UpdatedAt.Format(time.RFC3339),
	}
	if updated.ExternalID.Valid {
		resp.ExternalID = &updated.ExternalID.String
	}
	if updated.MappedRole.Valid {
		resp.MappedRole = &updated.MappedRole.String
	}
	if updated.MappedGroupID.Valid {
		s := updated.MappedGroupID.UUID.String()
		resp.MappedGroupID = &s
	}

	writeJSON(w, http.StatusOK, resp)
}

// ptrStringDiffers returns true if a *string value differs from a sql.NullString.
// nil means "no value" (cleared); NullString.Valid==false also means no value.
func ptrStringDiffers(ptr *string, ns sql.NullString) bool {
	if ptr == nil {
		return ns.Valid // was set, now cleared
	}
	if !ns.Valid {
		return true // was null, now set
	}
	return *ptr != ns.String
}

// ptrUUIDDiffers returns true if a *uuid.UUID value differs from a uuid.NullUUID.
func ptrUUIDDiffers(ptr *uuid.UUID, nu uuid.NullUUID) bool {
	if ptr == nil {
		return nu.Valid
	}
	if !nu.Valid {
		return true
	}
	return *ptr != nu.UUID
}
