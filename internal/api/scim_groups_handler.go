// ABOUTME: SCIM 2.0 Group endpoint handlers (RFC 7644 §3).
// ABOUTME: Mounted as chi handlers on /scim/v2/Groups. Supports create, get, list, replace, patch, delete.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
)

// scimGroupRequest is the JSON body for POST and PUT /Groups.
type scimGroupRequest struct {
	ExternalID  string            `json:"externalId"`
	DisplayName string            `json:"displayName"`
	Members     []SCIMGroupMember `json:"members"`
}

// memberFilterRE extracts a user UUID from a SCIM path filter expression like
// members[value eq "some-uuid"].
var memberFilterRE = regexp.MustCompile(`(?i)^members\[value\s+eq\s+"(.+)"\]$`)

// scimCreateGroup handles POST /Groups.
func (srv *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)

	var body scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid JSON body")
		return
	}

	if strings.TrimSpace(body.DisplayName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}

	var externalID *string
	if body.ExternalID != "" {
		externalID = &body.ExternalID
	}

	group, err := srv.store.CreateSCIMGroup(ctx, orgID, externalID, body.DisplayName)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			writeSCIMError(w, http.StatusConflict, "uniqueness", "group displayName already exists in this organization")
			return
		}
		slog.ErrorContext(ctx, "scim: create group", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Get default_role for role recomputation.
	cfg, err := srv.store.GetSCIMConfig(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get config for role recompute", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	defaultRole := "viewer"
	if cfg != nil {
		defaultRole = cfg.DefaultRole
	}

	// Process initial members.
	for _, m := range body.Members {
		userID, parseErr := uuid.Parse(m.Value)
		if parseErr != nil {
			continue
		}
		if addErr := srv.store.AddSCIMGroupMember(ctx, group.ID, userID, orgID); addErr != nil {
			slog.ErrorContext(ctx, "scim: add group member", "group_id", group.ID, "user_id", userID, "error", addErr)
			continue
		}
		srv.processGroupMemberAdd(ctx, orgID, userID, group.ID, group.MappedRole.String, group.MappedRole.Valid, group.MappedGroupID, defaultRole)
	}

	// Load members for response.
	memberIDs, err := srv.store.ListSCIMGroupMembers(ctx, group.ID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: list members after create", "error", err)
	}

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "create",
		EntityType: "scim_group",
		EntityID:   group.ID.String(),
		EntityName: group.DisplayName,
		Success:    true,
		Metadata:   map[string]any{"source": "scim", "scim_config_id": ctx.Value(ctxSCIMConfigID).(uuid.UUID).String()},
	})

	resp := srv.buildSCIMGroupResponse(r, group.ID.String(), group.ExternalID.String, group.DisplayName, group.CreatedAt.Format("2006-01-02T15:04:05Z"), group.UpdatedAt.Format("2006-01-02T15:04:05Z"), memberIDs)
	writeSCIMJSON(w, http.StatusCreated, resp)
}

// scimGetGroup handles GET /Groups/{id}.
func (srv *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groupIDStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}

	group, err := srv.store.GetSCIMGroup(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get group", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if group == nil {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}

	// Verify the group belongs to this org.
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)
	if group.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}

	memberIDs, err := srv.store.ListSCIMGroupMembers(ctx, group.ID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: list group members", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	resp := srv.buildSCIMGroupResponse(r, group.ID.String(), group.ExternalID.String, group.DisplayName, group.CreatedAt.Format("2006-01-02T15:04:05Z"), group.UpdatedAt.Format("2006-01-02T15:04:05Z"), memberIDs)
	writeSCIMJSON(w, http.StatusOK, resp)
}

// scimListGroups handles GET /Groups with optional filtering.
func (srv *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)

	filterStr := r.URL.Query().Get("filter")
	exprs, err := parseSCIMFilter(filterStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}

	groups, err := srv.store.ListSCIMGroups(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: list groups", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Apply filters in-memory (group counts are small).
	var filtered []any
	for _, g := range groups {
		if matchesSCIMGroupFilter(g.ID.String(), g.ExternalID.String, g.DisplayName, exprs) {
			memberIDs, mErr := srv.store.ListSCIMGroupMembers(ctx, g.ID)
			if mErr != nil {
				slog.ErrorContext(ctx, "scim: list group members for list", "group_id", g.ID, "error", mErr)
				continue
			}
			resp := srv.buildSCIMGroupResponse(r, g.ID.String(), g.ExternalID.String, g.DisplayName, g.CreatedAt.Format("2006-01-02T15:04:05Z"), g.UpdatedAt.Format("2006-01-02T15:04:05Z"), memberIDs)
			filtered = append(filtered, resp)
		}
	}

	if filtered == nil {
		filtered = []any{}
	}

	writeSCIMJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(filtered),
		ItemsPerPage: len(filtered),
		StartIndex:   1,
		Resources:    filtered,
	})
}

// scimReplaceGroup handles PUT /Groups/{id}.
func (srv *Server) scimReplaceGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)

	groupIDStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}

	group, err := srv.store.GetSCIMGroup(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get group for replace", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if group == nil || group.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}

	var body scimGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid JSON body")
		return
	}

	if strings.TrimSpace(body.DisplayName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}

	var externalID *string
	if body.ExternalID != "" {
		externalID = &body.ExternalID
	}

	if err := srv.store.UpdateSCIMGroup(ctx, groupID, body.DisplayName, externalID); err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			writeSCIMError(w, http.StatusConflict, "uniqueness", "group displayName already exists in this organization")
			return
		}
		slog.ErrorContext(ctx, "scim: update group", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Get config for role recomputation.
	cfg, err := srv.store.GetSCIMConfig(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get config for replace", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	defaultRole := "viewer"
	if cfg != nil {
		defaultRole = cfg.DefaultRole
	}

	// Diff members: current vs new.
	currentMembers, err := srv.store.ListSCIMGroupMembers(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: list members for diff", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	newMemberSet := make(map[uuid.UUID]bool, len(body.Members))
	for _, m := range body.Members {
		uid, parseErr := uuid.Parse(m.Value)
		if parseErr != nil {
			continue
		}
		newMemberSet[uid] = true
	}

	currentSet := make(map[uuid.UUID]bool, len(currentMembers))
	for _, uid := range currentMembers {
		currentSet[uid] = true
	}

	// Reload group to get the current mapped_role and mapped_group_id.
	group, _ = srv.store.GetSCIMGroup(ctx, groupID)

	// Add new members.
	for uid := range newMemberSet {
		if !currentSet[uid] {
			if addErr := srv.store.AddSCIMGroupMember(ctx, groupID, uid, orgID); addErr != nil {
				slog.ErrorContext(ctx, "scim: add member in replace", "user_id", uid, "error", addErr)
				continue
			}
			srv.processGroupMemberAdd(ctx, orgID, uid, groupID, group.MappedRole.String, group.MappedRole.Valid, group.MappedGroupID, defaultRole)
		}
	}

	// Remove absent members.
	for _, uid := range currentMembers {
		if !newMemberSet[uid] {
			if rmErr := srv.store.RemoveSCIMGroupMember(ctx, groupID, uid); rmErr != nil {
				slog.ErrorContext(ctx, "scim: remove member in replace", "user_id", uid, "error", rmErr)
				continue
			}
			srv.processGroupMemberRemove(ctx, orgID, uid, groupID, group.MappedRole.String, group.MappedRole.Valid, group.MappedGroupID, defaultRole)
		}
	}

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "scim_group",
		EntityID:   groupID.String(),
		EntityName: body.DisplayName,
		Success:    true,
		Metadata:   map[string]any{"source": "scim", "scim_config_id": ctx.Value(ctxSCIMConfigID).(uuid.UUID).String()},
	})

	// Reload for response.
	memberIDs, _ := srv.store.ListSCIMGroupMembers(ctx, groupID)
	group, _ = srv.store.GetSCIMGroup(ctx, groupID)
	resp := srv.buildSCIMGroupResponse(r, group.ID.String(), group.ExternalID.String, group.DisplayName, group.CreatedAt.Format("2006-01-02T15:04:05Z"), group.UpdatedAt.Format("2006-01-02T15:04:05Z"), memberIDs)
	writeSCIMJSON(w, http.StatusOK, resp)
}

// scimPatchGroup handles PATCH /Groups/{id}.
func (srv *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)

	groupIDStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}

	group, err := srv.store.GetSCIMGroup(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get group for patch", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if group == nil || group.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "group not found")
		return
	}

	var patch SCIMPatchOp
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid JSON body")
		return
	}

	// Get config for role recomputation.
	cfg, err := srv.store.GetSCIMConfig(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get config for patch", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	defaultRole := "viewer"
	if cfg != nil {
		defaultRole = cfg.DefaultRole
	}

	for _, op := range patch.Operations {
		opLower := strings.ToLower(op.Op)
		pathLower := strings.ToLower(op.Path)

		switch opLower {
		case "add":
			if pathLower == "members" {
				userIDs := extractMemberValues(op.Value)
				for _, userID := range userIDs {
					if addErr := srv.store.AddSCIMGroupMember(ctx, group.ID, userID, orgID); addErr != nil {
						slog.ErrorContext(ctx, "scim: patch add member", "user_id", userID, "error", addErr)
						continue
					}
					srv.processGroupMemberAdd(ctx, orgID, userID, group.ID, group.MappedRole.String, group.MappedRole.Valid, group.MappedGroupID, defaultRole)
				}
			}

		case "remove":
			userIDs := srv.extractRemoveTargets(op)
			for _, userID := range userIDs {
				if rmErr := srv.store.RemoveSCIMGroupMember(ctx, group.ID, userID); rmErr != nil {
					slog.ErrorContext(ctx, "scim: patch remove member", "user_id", userID, "error", rmErr)
					continue
				}
				srv.processGroupMemberRemove(ctx, orgID, userID, group.ID, group.MappedRole.String, group.MappedRole.Valid, group.MappedGroupID, defaultRole)
			}

		case "replace":
			if pathLower == "displayname" {
				var newName string
				if err := json.Unmarshal(op.Value, &newName); err != nil {
					writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName value must be a string")
					return
				}
				if strings.TrimSpace(newName) == "" {
					writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName cannot be empty")
					return
				}
				if updateErr := srv.store.UpdateSCIMGroup(ctx, group.ID, newName, nil); updateErr != nil {
					if strings.Contains(updateErr.Error(), "duplicate key") || strings.Contains(updateErr.Error(), "unique constraint") {
						writeSCIMError(w, http.StatusConflict, "uniqueness", "group displayName already exists in this organization")
						return
					}
					slog.ErrorContext(ctx, "scim: patch replace displayName", "error", updateErr)
					writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
					return
				}
			} else {
				writeSCIMError(w, http.StatusBadRequest, "invalidPath", fmt.Sprintf("unrecognized attribute path: %q", op.Path))
				return
			}

		default:
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", fmt.Sprintf("unsupported operation: %q", op.Op))
			return
		}
	}

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "scim_group",
		EntityID:   groupID.String(),
		EntityName: group.DisplayName,
		Success:    true,
		Metadata:   map[string]any{"source": "scim", "scim_config_id": ctx.Value(ctxSCIMConfigID).(uuid.UUID).String()},
	})

	// Reload for response.
	group, _ = srv.store.GetSCIMGroup(ctx, groupID)
	memberIDs, _ := srv.store.ListSCIMGroupMembers(ctx, groupID)
	resp := srv.buildSCIMGroupResponse(r, group.ID.String(), group.ExternalID.String, group.DisplayName, group.CreatedAt.Format("2006-01-02T15:04:05Z"), group.UpdatedAt.Format("2006-01-02T15:04:05Z"), memberIDs)
	writeSCIMJSON(w, http.StatusOK, resp)
}

// scimDeleteGroup handles DELETE /Groups/{id}.
func (srv *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID)

	groupIDStr := chi.URLParam(r, "id")
	groupID, err := uuid.Parse(groupIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid group id")
		return
	}

	group, err := srv.store.GetSCIMGroup(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get group for delete", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if group == nil || group.OrgID != orgID {
		// Idempotent — already deleted returns 204.
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Collect affected non-exempt users before deletion.
	memberIDs, err := srv.store.ListSCIMGroupMembers(ctx, groupID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: list members for delete", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Get config for role recomputation.
	cfg, err := srv.store.GetSCIMConfig(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get config for delete", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	defaultRole := "viewer"
	if cfg != nil {
		defaultRole = cfg.DefaultRole
	}

	// Delete the group (CASCADE deletes scim_group_members).
	if err := srv.store.DeleteSCIMGroup(ctx, groupID); err != nil {
		slog.ErrorContext(ctx, "scim: delete group", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Recompute roles for affected non-exempt users.
	for _, uid := range memberIDs {
		member, mErr := srv.store.GetOrgMemberFull(ctx, orgID, uid)
		if mErr != nil || member == nil {
			continue
		}
		if member.ScimExempt {
			continue
		}
		if roleErr := srv.recomputeSCIMRole(ctx, orgID, uid, defaultRole); roleErr != nil {
			slog.ErrorContext(ctx, "scim: recompute role after group delete", "user_id", uid, "error", roleErr)
		}
	}
	// Design decision (§3.4): do NOT remove users from mapped notification group on group delete.

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "delete",
		EntityType: "scim_group",
		EntityID:   groupID.String(),
		EntityName: group.DisplayName,
		Success:    true,
		Metadata:   map[string]any{"source": "scim", "scim_config_id": ctx.Value(ctxSCIMConfigID).(uuid.UUID).String()},
	})

	w.WriteHeader(http.StatusNoContent)
}

// processGroupMemberAdd handles role recomputation and notification group sync
// when a user is added to a SCIM group.
func (srv *Server) processGroupMemberAdd(ctx context.Context, orgID, userID, scimGroupID uuid.UUID, _ string, hasMappedRole bool, mappedGroupID uuid.NullUUID, defaultRole string) {
	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil || member == nil {
		return
	}
	if member.ScimExempt {
		return
	}

	if hasMappedRole {
		if err := srv.recomputeSCIMRole(ctx, orgID, userID, defaultRole); err != nil {
			slog.ErrorContext(ctx, "scim: recompute role on add", "user_id", userID, "error", err)
		}
	}

	if mappedGroupID.Valid {
		if err := srv.syncNotifGroupAdd(ctx, orgID, userID, mappedGroupID.UUID, scimGroupID); err != nil {
			slog.ErrorContext(ctx, "scim: sync notif group add", "user_id", userID, "error", err)
		}
	}
}

// processGroupMemberRemove handles role recomputation and notification group sync
// when a user is removed from a SCIM group.
func (srv *Server) processGroupMemberRemove(ctx context.Context, orgID, userID, scimGroupID uuid.UUID, _ string, hasMappedRole bool, mappedGroupID uuid.NullUUID, defaultRole string) {
	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil || member == nil {
		return
	}
	if member.ScimExempt {
		return
	}

	if hasMappedRole {
		if err := srv.recomputeSCIMRole(ctx, orgID, userID, defaultRole); err != nil {
			slog.ErrorContext(ctx, "scim: recompute role on remove", "user_id", userID, "error", err)
		}
	}

	if mappedGroupID.Valid {
		if err := srv.syncNotifGroupRemove(ctx, orgID, userID, mappedGroupID.UUID, scimGroupID); err != nil {
			slog.ErrorContext(ctx, "scim: sync notif group remove", "user_id", userID, "error", err)
		}
	}
}

// extractMemberValues parses member references from a SCIM PATCH value field.
// Handles both: [{value: "uuid"}, ...] and single {value: "uuid"}.
func extractMemberValues(raw json.RawMessage) []uuid.UUID {
	// Try array of member objects.
	var members []SCIMGroupMember
	if err := json.Unmarshal(raw, &members); err == nil {
		result := make([]uuid.UUID, 0, len(members))
		for _, m := range members {
			uid, err := uuid.Parse(m.Value)
			if err == nil {
				result = append(result, uid)
			}
		}
		return result
	}

	// Try single member object.
	var single SCIMGroupMember
	if err := json.Unmarshal(raw, &single); err == nil {
		uid, err := uuid.Parse(single.Value)
		if err == nil {
			return []uuid.UUID{uid}
		}
	}

	return nil
}

// extractRemoveTargets extracts user UUIDs from a remove operation.
// Supports two formats:
//  1. Standard: path = members[value eq "user-uuid"]
//  2. Entra ID: path = "members", value = [{value: "user-uuid"}, ...]
func (srv *Server) extractRemoveTargets(op SCIMPatchOperation) []uuid.UUID {
	// Format 1: path filter expression.
	if matches := memberFilterRE.FindStringSubmatch(op.Path); len(matches) == 2 {
		uid, err := uuid.Parse(matches[1])
		if err == nil {
			return []uuid.UUID{uid}
		}
	}

	// Format 2: Entra ID value array (path is "members", values in body).
	if strings.EqualFold(op.Path, "members") && len(op.Value) > 0 {
		return extractMemberValues(op.Value)
	}

	return nil
}

// matchesSCIMGroupFilter checks if a group matches the given SCIM filter expressions.
func matchesSCIMGroupFilter(id, externalID, displayName string, exprs []SCIMFilterExpr) bool {
	if len(exprs) == 0 {
		return true
	}
	for _, expr := range exprs {
		attrLower := strings.ToLower(expr.Attr)
		switch attrLower {
		case "displayname":
			if expr.Value != displayName {
				return false
			}
		case "externalid":
			if expr.Value != externalID {
				return false
			}
		case "id":
			if expr.Value != id {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// buildSCIMGroupResponse constructs a SCIMGroup response.
func (srv *Server) buildSCIMGroupResponse(r *http.Request, id, externalID, displayName, created, lastModified string, memberIDs []uuid.UUID) SCIMGroup {
	members := make([]SCIMGroupMember, 0, len(memberIDs))
	for _, uid := range memberIDs {
		members = append(members, SCIMGroupMember{
			Value: uid.String(),
			Ref:   fmt.Sprintf("%s/Users/%s", scimBaseURL(r), uid.String()),
		})
	}

	return SCIMGroup{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ID:          id,
		ExternalID:  externalID,
		DisplayName: displayName,
		Members:     members,
		Meta: SCIMMeta{
			ResourceType: "Group",
			Created:      created,
			LastModified: lastModified,
			Location:     fmt.Sprintf("%s/Groups/%s", scimBaseURL(r), id),
		},
	}
}

// scimBaseURL returns the SCIM v2 base URL derived from the request.
// For a request to /api/v1/orgs/{org_id}/scim/v2/Groups/..., returns
// the URL up to and including /scim/v2.
func scimBaseURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	}
	path := r.URL.Path
	if idx := strings.Index(path, "/scim/v2"); idx >= 0 {
		path = path[:idx+len("/scim/v2")]
	}
	return fmt.Sprintf("%s://%s%s", scheme, r.Host, path)
}
