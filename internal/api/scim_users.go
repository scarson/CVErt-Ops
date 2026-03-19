// ABOUTME: SCIM 2.0 User resource handlers (RFC 7643/7644).
// ABOUTME: Implements create, get, list, replace (PUT), patch, and delete for user provisioning.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/tier"
)

// scimUserRequest is the JSON body for POST and PUT /Users.
type scimUserRequest struct {
	Schemas     []string `json:"schemas"`
	ExternalID  string   `json:"externalId"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      *bool    `json:"active,omitempty"`
}

// scimProvider returns the SCIM identity provider string for the given config ID.
func scimProvider(scimConfigID uuid.UUID) string {
	return fmt.Sprintf("scim:%s", scimConfigID)
}

// scimUserLocation returns the SCIM resource location for a user.
func scimUserLocation(r *http.Request, orgID, userID uuid.UUID) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/api/v1/orgs/%s/scim/v2/Users/%s",
		scheme, r.Host, orgID, userID)
}

// buildSCIMUser constructs a SCIMUser response from component data.
func buildSCIMUser(r *http.Request, orgID, userID uuid.UUID, email, displayName, externalID string, active bool, createdAt, updatedAt time.Time) SCIMUser {
	return SCIMUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:          userID.String(),
		ExternalID:  externalID,
		UserName:    email,
		DisplayName: displayName,
		Active:      active,
		Meta: SCIMMeta{
			ResourceType: "User",
			Created:      createdAt.UTC().Format(time.RFC3339),
			LastModified: updatedAt.UTC().Format(time.RFC3339),
			Location:     scimUserLocation(r, orgID, userID),
		},
	}
}

// scimAuditMeta returns the standard SCIM audit metadata map.
func scimAuditMeta(scimConfigID uuid.UUID) map[string]any {
	return map[string]any{"source": "scim", "scim_config_id": scimConfigID.String()}
}

// scimCreateUser handles POST /Users — provision a new user.
func (srv *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	provider := scimProvider(scimConfigID)
	ctx := r.Context()

	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid JSON body")
		return
	}

	if strings.TrimSpace(req.UserName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}

	if strings.TrimSpace(req.ExternalID) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "externalId is required")
		return
	}

	slog.InfoContext(ctx, "scim create user",
		slog.String("org_id", orgID.String()),
		slog.String("scim_config_id", scimConfigID.String()),
		slog.String("external_id", req.ExternalID),
		slog.String("user_name", req.UserName),
	)

	// Step 1: Check user_identities for existing SCIM link.
	existingUser, err := srv.store.GetUserByProviderID(ctx, provider, req.ExternalID)
	if err != nil {
		slog.ErrorContext(ctx, "scim create: lookup by provider id", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	if existingUser != nil {
		// Found by externalId. Check org membership.
		member, err := srv.store.GetOrgMemberFull(ctx, orgID, existingUser.ID)
		if err != nil {
			slog.ErrorContext(ctx, "scim create: get member for existing user", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}

		if member != nil {
			if !member.DeactivatedAt.Valid {
				// Active member — idempotent return.
				identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, existingUser.ID)
				extID := req.ExternalID
				if identity != nil {
					extID = identity.ProviderUserID
				}
				writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, existingUser.ID,
					existingUser.Email, existingUser.DisplayName, extID,
					true, member.CreatedAt, member.UpdatedAt))
				return
			}

			// Deactivated member.
			if member.ScimExempt {
				slog.WarnContext(ctx, "scim create: exempt user, skipping reactivation",
					slog.String("user_id", existingUser.ID.String()))
				srv.fireSCIMEvent(ctx, secure.EventSCIMExemptSuppressed, &orgID)
				identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, existingUser.ID)
				extID := req.ExternalID
				if identity != nil {
					extID = identity.ProviderUserID
				}
				writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, existingUser.ID,
					existingUser.Email, existingUser.DisplayName, extID,
					false, member.CreatedAt, member.UpdatedAt))
				return
			}

			// Reactivate.
			if err := srv.store.ReactivateOrgMember(ctx, orgID, existingUser.ID); err != nil {
				slog.ErrorContext(ctx, "scim create: reactivate member", "error", err)
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}

			// Re-read for updated timestamps.
			member, _ = srv.store.GetOrgMemberFull(ctx, orgID, existingUser.ID)
			identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, existingUser.ID)
			extID := req.ExternalID
			if identity != nil {
				extID = identity.ProviderUserID
			}
			srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
				OrgID:      orgID,
				Action:     "update",
				EntityType: "member",
				EntityID:   existingUser.ID.String(),
				Success:    true,
				NewState:   map[string]any{"active": true},
				Metadata:   scimAuditMeta(scimConfigID),
			})
			createdAt := existingUser.CreatedAt
			updatedAt := existingUser.CreatedAt
			if member != nil {
				createdAt = member.CreatedAt
				updatedAt = member.UpdatedAt
			}
			writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, existingUser.ID,
				existingUser.Email, existingUser.DisplayName, extID,
				true, createdAt, updatedAt))
			return
		}
		// User exists by provider ID but not a member — fall through to create membership.
	}

	// Step 2: Lookup users by email.
	if existingUser == nil {
		existingUser, err = srv.store.GetUserByEmail(ctx, req.UserName)
		if err != nil {
			slog.ErrorContext(ctx, "scim create: lookup by email", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	}

	if existingUser != nil {
		// Found by email (or by provider but not a member).
		member, err := srv.store.GetOrgMemberFull(ctx, orgID, existingUser.ID)
		if err != nil {
			slog.ErrorContext(ctx, "scim create: get member for email user", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}

		// Link SCIM identity (withBypassTx — global table).
		if err := srv.store.UpsertUserIdentity(ctx, existingUser.ID, provider, req.ExternalID, req.UserName); err != nil {
			slog.ErrorContext(ctx, "scim create: link identity", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}

		if member != nil {
			// Already a member.
			if member.DeactivatedAt.Valid && !member.ScimExempt {
				// Reactivate.
				if err := srv.store.ReactivateOrgMember(ctx, orgID, existingUser.ID); err != nil {
					slog.ErrorContext(ctx, "scim create: reactivate email user", "error", err)
					writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
					return
				}
				srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
					OrgID:      orgID,
					Action:     "update",
					EntityType: "member",
					EntityID:   existingUser.ID.String(),
					Success:    true,
					NewState:   map[string]any{"active": true},
					Metadata:   scimAuditMeta(scimConfigID),
				})
			} else if member.DeactivatedAt.Valid && member.ScimExempt {
				slog.WarnContext(ctx, "scim create: exempt user, skipping reactivation",
					slog.String("user_id", existingUser.ID.String()))
				srv.fireSCIMEvent(ctx, secure.EventSCIMExemptSuppressed, &orgID)
			}

			// Re-read for response.
			member, _ = srv.store.GetOrgMemberFull(ctx, orgID, existingUser.ID)
			active := member != nil && !member.DeactivatedAt.Valid
			createdAt := existingUser.CreatedAt
			updatedAt := existingUser.CreatedAt
			if member != nil {
				createdAt = member.CreatedAt
				updatedAt = member.UpdatedAt
			}
			writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, existingUser.ID,
				existingUser.Email, existingUser.DisplayName, req.ExternalID,
				active, createdAt, updatedAt))
			return
		}

		// Not a member — check tier limit and create membership.
		if err := srv.checkSCIMMemberLimit(ctx, orgID); err != nil {
			writeSCIMError(w, http.StatusForbidden, "", "member limit reached for this organization's tier")
			return
		}

		// Get default role from SCIM config.
		defaultRole := srv.getSCIMDefaultRole(ctx, orgID)

		if err := srv.store.CreateOrgMember(ctx, orgID, existingUser.ID, defaultRole); err != nil {
			slog.ErrorContext(ctx, "scim create: create membership for email user", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}

		srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
			OrgID:      orgID,
			Action:     "create",
			EntityType: "member",
			EntityID:   existingUser.ID.String(),
			Success:    true,
			NewState:   map[string]any{"role": defaultRole},
			Metadata:   scimAuditMeta(scimConfigID),
		})

		member, _ = srv.store.GetOrgMemberFull(ctx, orgID, existingUser.ID)
		createdAt := existingUser.CreatedAt
		updatedAt := existingUser.CreatedAt
		if member != nil {
			createdAt = member.CreatedAt
			updatedAt = member.UpdatedAt
		}
		writeSCIMJSON(w, http.StatusCreated, buildSCIMUser(r, orgID, existingUser.ID,
			existingUser.Email, existingUser.DisplayName, req.ExternalID,
			true, createdAt, updatedAt))
		return
	}

	// Step 3: Create new user.
	if err := srv.checkSCIMMemberLimit(ctx, orgID); err != nil {
		writeSCIMError(w, http.StatusForbidden, "", "member limit reached for this organization's tier")
		return
	}

	displayName := req.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = req.UserName
	}

	// Tx 1: create user + identity (withBypassTx — global tables).
	newUser, err := srv.store.CreateUser(ctx, req.UserName, displayName, "", 0)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			writeSCIMError(w, http.StatusConflict, "uniqueness", "userName already exists")
			return
		}
		slog.ErrorContext(ctx, "scim create: create user", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	if err := srv.store.UpsertUserIdentity(ctx, newUser.ID, provider, req.ExternalID, req.UserName); err != nil {
		slog.ErrorContext(ctx, "scim create: create identity", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Tx 2: create org membership (withOrgTx — org-scoped).
	defaultRole := srv.getSCIMDefaultRole(ctx, orgID)

	if err := srv.store.CreateOrgMember(ctx, orgID, newUser.ID, defaultRole); err != nil {
		slog.ErrorContext(ctx, "scim create: create membership", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
		OrgID:      orgID,
		Action:     "create",
		EntityType: "member",
		EntityID:   newUser.ID.String(),
		Success:    true,
		NewState:   map[string]any{"role": defaultRole},
		Metadata:   scimAuditMeta(scimConfigID),
	})
	srv.fireSCIMEvent(ctx, secure.EventSCIMUserProvisioned, &orgID)

	member, _ := srv.store.GetOrgMemberFull(ctx, orgID, newUser.ID)
	createdAt := newUser.CreatedAt
	updatedAt := newUser.CreatedAt
	if member != nil {
		createdAt = member.CreatedAt
		updatedAt = member.UpdatedAt
	}
	writeSCIMJSON(w, http.StatusCreated, buildSCIMUser(r, orgID, newUser.ID,
		newUser.Email, newUser.DisplayName, req.ExternalID,
		true, createdAt, updatedAt))
}

// scimGetUser handles GET /Users/{id}.
func (srv *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	provider := scimProvider(scimConfigID)
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid user id")
		return
	}

	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		slog.ErrorContext(ctx, "scim get user: lookup", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if member == nil {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}

	// Get externalId from identity if exists.
	externalID := ""
	identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, userID)
	if identity != nil {
		externalID = identity.ProviderUserID
	}

	active := !member.DeactivatedAt.Valid
	writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, userID,
		member.Email, member.DisplayName, externalID,
		active, member.CreatedAt, member.UpdatedAt))
}

// scimListUsers handles GET /Users with optional SCIM filtering.
func (srv *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	provider := scimProvider(scimConfigID)
	ctx := r.Context()

	// Parse pagination params.
	startIndex := 1
	count := 100
	if si := r.URL.Query().Get("startIndex"); si != "" {
		if v, err := strconv.Atoi(si); err == nil && v >= 1 {
			startIndex = v
		}
	}
	if c := r.URL.Query().Get("count"); c != "" {
		if v, err := strconv.Atoi(c); err == nil && v >= 0 {
			count = v
		}
	}

	// Parse filters.
	filterStr := r.URL.Query().Get("filter")
	filters, err := parseSCIMFilter(filterStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", err.Error())
		return
	}

	// Validate filter attributes.
	for _, f := range filters {
		switch strings.ToLower(f.Attr) {
		case "username", "externalid", "id", "active":
			// supported
		default:
			writeSCIMError(w, http.StatusBadRequest, "invalidFilter",
				fmt.Sprintf("unsupported filter attribute: %q", f.Attr))
			return
		}
	}

	// List all org members (including deactivated).
	members, err := srv.store.ListOrgMembers(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim list users: list members", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Apply filters.
	type scimMember struct {
		UserID      uuid.UUID
		Email       string
		DisplayName string
		Active      bool
		ExternalID  string
		CreatedAt   time.Time
		UpdatedAt   time.Time
	}

	var filtered []scimMember
	for _, m := range members {
		active := !m.DeactivatedAt.Valid

		// Get external ID for this member.
		extID := ""
		identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, m.UserID)
		if identity != nil {
			extID = identity.ProviderUserID
		}

		// Apply filters.
		match := true
		for _, f := range filters {
			switch strings.ToLower(f.Attr) {
			case "username":
				if !strings.EqualFold(m.Email, f.Value) {
					match = false
				}
			case "externalid":
				if extID != f.Value {
					match = false
				}
			case "id":
				if m.UserID.String() != f.Value {
					match = false
				}
			case "active":
				filterActive := strings.EqualFold(f.Value, "true")
				if active != filterActive {
					match = false
				}
			}
		}

		if match {
			filtered = append(filtered, scimMember{
				UserID:      m.UserID,
				Email:       m.Email,
				DisplayName: m.DisplayName,
				Active:      active,
				ExternalID:  extID,
				CreatedAt:   m.CreatedAt,
				UpdatedAt:   m.UpdatedAt,
			})
		}
	}

	totalResults := len(filtered)

	// Apply pagination (SCIM startIndex is 1-based).
	offset := startIndex - 1
	if offset < 0 {
		offset = 0
	}
	if offset > len(filtered) {
		offset = len(filtered)
	}
	end := offset + count
	if end > len(filtered) {
		end = len(filtered)
	}
	page := filtered[offset:end]

	resources := make([]any, 0, len(page))
	for _, m := range page {
		resources = append(resources, buildSCIMUser(r, orgID, m.UserID,
			m.Email, m.DisplayName, m.ExternalID,
			m.Active, m.CreatedAt, m.UpdatedAt))
	}

	writeSCIMJSON(w, http.StatusOK, SCIMListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: totalResults,
		ItemsPerPage: len(page),
		StartIndex:   startIndex,
		Resources:    resources,
	})
}

// scimReplaceUser handles PUT /Users/{id} — full resource replacement.
func (srv *Server) scimReplaceUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	provider := scimProvider(scimConfigID)
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid user id")
		return
	}

	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid JSON body")
		return
	}

	if strings.TrimSpace(req.UserName) == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}

	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		slog.ErrorContext(ctx, "scim replace user: lookup", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if member == nil {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}

	// SCIM-exempt: return current state without modification.
	if member.ScimExempt {
		slog.WarnContext(ctx, "scim replace user: exempt user, skipping",
			slog.String("user_id", userID.String()))
		srv.fireSCIMEvent(ctx, secure.EventSCIMExemptSuppressed, &orgID)
		identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, userID)
		extID := ""
		if identity != nil {
			extID = identity.ProviderUserID
		}
		writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, userID,
			member.Email, member.DisplayName, extID,
			!member.DeactivatedAt.Valid, member.CreatedAt, member.UpdatedAt))
		return
	}

	// Determine active flag — default to true if omitted.
	active := true
	if req.Active != nil {
		active = *req.Active
	}

	// displayName falls back to userName if omitted.
	displayName := req.DisplayName
	if strings.TrimSpace(displayName) == "" {
		displayName = req.UserName
	}

	// Update user profile (withBypassTx — global table).
	if err := srv.store.UpdateUserProfile(ctx, userID, req.UserName, displayName); err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
			writeSCIMError(w, http.StatusConflict, "uniqueness", "userName already exists")
			return
		}
		slog.ErrorContext(ctx, "scim replace user: update profile", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Update externalId if provided.
	if req.ExternalID != "" {
		if err := srv.store.UpsertUserIdentity(ctx, userID, provider, req.ExternalID, req.UserName); err != nil {
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
				writeSCIMError(w, http.StatusConflict, "uniqueness", "externalId already linked to another user")
				return
			}
			slog.ErrorContext(ctx, "scim replace user: update identity", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	}

	// Handle active/inactive state.
	wasActive := !member.DeactivatedAt.Valid
	if active && !wasActive {
		if err := srv.store.ReactivateOrgMember(ctx, orgID, userID); err != nil {
			slog.ErrorContext(ctx, "scim replace user: reactivate", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	} else if !active && wasActive {
		// Sole-owner protection.
		if member.Role == "owner" {
			count, err := srv.store.CountActiveOrgOwners(ctx, orgID)
			if err != nil {
				slog.ErrorContext(ctx, "scim replace user: count owners", "error", err)
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}
			if count <= 1 {
				srv.fireSCIMEvent(ctx, secure.EventSCIMSoleOwnerProtected, &orgID)
				writeSCIMError(w, http.StatusBadRequest, "", "cannot deactivate the sole owner")
				return
			}
		}
		if err := srv.store.DeactivateOrgMember(ctx, orgID, userID); err != nil {
			slog.ErrorContext(ctx, "scim replace user: deactivate", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	}

	srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "member",
		EntityID:   userID.String(),
		Success:    true,
		Metadata:   scimAuditMeta(scimConfigID),
	})

	// Re-read for response.
	member, _ = srv.store.GetOrgMemberFull(ctx, orgID, userID)
	extID := req.ExternalID
	if extID == "" {
		identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, userID)
		if identity != nil {
			extID = identity.ProviderUserID
		}
	}
	memberActive := member != nil && !member.DeactivatedAt.Valid
	createdAt := time.Now()
	updatedAt := time.Now()
	if member != nil {
		createdAt = member.CreatedAt
		updatedAt = member.UpdatedAt
	}
	writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, userID,
		req.UserName, displayName, extID,
		memberActive, createdAt, updatedAt))
}

// scimPatchUser handles PATCH /Users/{id} — partial update.
func (srv *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	provider := scimProvider(scimConfigID)
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid user id")
		return
	}

	var patchOp SCIMPatchOp
	if err := json.NewDecoder(r.Body).Decode(&patchOp); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid JSON body")
		return
	}

	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		slog.ErrorContext(ctx, "scim patch user: lookup", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if member == nil {
		writeSCIMError(w, http.StatusNotFound, "", "user not found")
		return
	}

	// SCIM-exempt: return current state without modification.
	if member.ScimExempt {
		slog.WarnContext(ctx, "scim patch user: exempt user, skipping",
			slog.String("user_id", userID.String()))
		srv.fireSCIMEvent(ctx, secure.EventSCIMExemptSuppressed, &orgID)
		identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, userID)
		extID := ""
		if identity != nil {
			extID = identity.ProviderUserID
		}
		writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, userID,
			member.Email, member.DisplayName, extID,
			!member.DeactivatedAt.Valid, member.CreatedAt, member.UpdatedAt))
		return
	}

	// Process each operation.
	for _, op := range patchOp.Operations {
		opLower := strings.ToLower(op.Op)
		if opLower != "replace" && opLower != "add" {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue",
				fmt.Sprintf("unsupported operation: %q", op.Op))
			return
		}

		path := strings.ToLower(op.Path)

		switch path {
		case "active":
			active, err := parseSCIMBool(op.Value)
			if err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue",
					fmt.Sprintf("invalid active value: %v", err))
				return
			}
			wasActive := !member.DeactivatedAt.Valid
			if !active && wasActive {
				// Sole-owner protection.
				if member.Role == "owner" {
					count, err := srv.store.CountActiveOrgOwners(ctx, orgID)
					if err != nil {
						slog.ErrorContext(ctx, "scim patch: count owners", "error", err)
						writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
						return
					}
					if count <= 1 {
						srv.fireSCIMEvent(ctx, secure.EventSCIMSoleOwnerProtected, &orgID)
						writeSCIMError(w, http.StatusBadRequest, "", "cannot deactivate the sole owner")
						return
					}
				}
				if err := srv.store.DeactivateOrgMember(ctx, orgID, userID); err != nil {
					slog.ErrorContext(ctx, "scim patch: deactivate", "error", err)
					writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
					return
				}
			} else if active && !wasActive {
				if err := srv.store.ReactivateOrgMember(ctx, orgID, userID); err != nil {
					slog.ErrorContext(ctx, "scim patch: reactivate", "error", err)
					writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
					return
				}
			}

		case "username":
			var userName string
			if err := json.Unmarshal(op.Value, &userName); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName must be a string")
				return
			}
			if strings.TrimSpace(userName) == "" {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName cannot be empty")
				return
			}
			if err := srv.store.UpdateUserEmail(ctx, userID, userName); err != nil {
				if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
					writeSCIMError(w, http.StatusConflict, "uniqueness", "userName already exists")
					return
				}
				slog.ErrorContext(ctx, "scim patch: update email", "error", err)
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}

		case "displayname":
			var displayName string
			if err := json.Unmarshal(op.Value, &displayName); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName must be a string")
				return
			}
			if err := srv.store.UpdateUserDisplayName(ctx, userID, displayName); err != nil {
				slog.ErrorContext(ctx, "scim patch: update display name", "error", err)
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}

		case "externalid":
			var externalID string
			if err := json.Unmarshal(op.Value, &externalID); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "externalId must be a string")
				return
			}
			if err := srv.store.UpsertUserIdentity(ctx, userID, provider, externalID, member.Email); err != nil {
				if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique") {
					writeSCIMError(w, http.StatusConflict, "uniqueness", "externalId already linked to another user")
					return
				}
				slog.ErrorContext(ctx, "scim patch: update external id", "error", err)
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}

		case "":
			// Entra ID sometimes sends replace ops without a path, with the value as an object.
			// e.g., {"op": "Replace", "value": {"active": false}}
			var valMap map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &valMap); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "pathless operation value must be an object")
				return
			}
			for attr, val := range valMap {
				switch strings.ToLower(attr) {
				case "active":
					active, err := parseSCIMBool(val)
					if err != nil {
						writeSCIMError(w, http.StatusBadRequest, "invalidValue",
							fmt.Sprintf("invalid active value: %v", err))
						return
					}
					wasActive := !member.DeactivatedAt.Valid
					if !active && wasActive {
						if member.Role == "owner" {
							count, err := srv.store.CountActiveOrgOwners(ctx, orgID)
							if err != nil {
								slog.ErrorContext(ctx, "scim patch: count owners (pathless)", "error", err)
								writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
								return
							}
							if count <= 1 {
								srv.fireSCIMEvent(ctx, secure.EventSCIMSoleOwnerProtected, &orgID)
								writeSCIMError(w, http.StatusBadRequest, "", "cannot deactivate the sole owner")
								return
							}
						}
						if err := srv.store.DeactivateOrgMember(ctx, orgID, userID); err != nil {
							slog.ErrorContext(ctx, "scim patch: deactivate (pathless)", "error", err)
							writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
							return
						}
					} else if active && !wasActive {
						if err := srv.store.ReactivateOrgMember(ctx, orgID, userID); err != nil {
							slog.ErrorContext(ctx, "scim patch: reactivate (pathless)", "error", err)
							writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
							return
						}
					}
				default:
					// Ignore unsupported pathless attributes — IdPs may send extras.
				}
			}

		default:
			// Ignore unsupported paths — SCIM spec says unknown paths should not error.
			slog.WarnContext(ctx, "scim patch: ignoring unsupported path",
				slog.String("path", op.Path))
		}
	}

	srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "member",
		EntityID:   userID.String(),
		Success:    true,
		Metadata:   scimAuditMeta(scimConfigID),
	})

	// Re-read for response.
	member, _ = srv.store.GetOrgMemberFull(ctx, orgID, userID)
	user, _ := srv.store.GetUserByID(ctx, userID)
	identity, _ := srv.store.GetIdentityByProviderAndUser(ctx, provider, userID)
	extID := ""
	if identity != nil {
		extID = identity.ProviderUserID
	}
	email := ""
	dName := ""
	if user != nil {
		email = user.Email
		dName = user.DisplayName
	}
	memberActive := member != nil && !member.DeactivatedAt.Valid
	createdAt := time.Now()
	updatedAt := time.Now()
	if member != nil {
		createdAt = member.CreatedAt
		updatedAt = member.UpdatedAt
	}
	writeSCIMJSON(w, http.StatusOK, buildSCIMUser(r, orgID, userID,
		email, dName, extID,
		memberActive, createdAt, updatedAt))
}

// scimDeleteUser handles DELETE /Users/{id} — soft deactivation.
func (srv *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID := r.Context().Value(ctxOrgID).(uuid.UUID)
	scimConfigID := r.Context().Value(ctxSCIMConfigID).(uuid.UUID)
	ctx := r.Context()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", "invalid user id")
		return
	}

	member, err := srv.store.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		slog.ErrorContext(ctx, "scim delete user: lookup", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	// Not found — 204 (idempotent).
	if member == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// SCIM-exempt: return 204 without modification.
	if member.ScimExempt {
		slog.WarnContext(ctx, "scim delete user: exempt user, skipping",
			slog.String("user_id", userID.String()))
		srv.fireSCIMEvent(ctx, secure.EventSCIMExemptSuppressed, &orgID)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Already deactivated — 204 (idempotent).
	if member.DeactivatedAt.Valid {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Sole-owner protection.
	if member.Role == "owner" {
		count, err := srv.store.CountActiveOrgOwners(ctx, orgID)
		if err != nil {
			slog.ErrorContext(ctx, "scim delete user: count owners", "error", err)
			writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
			return
		}
		if count <= 1 {
			srv.fireSCIMEvent(ctx, secure.EventSCIMSoleOwnerProtected, &orgID)
			writeSCIMError(w, http.StatusBadRequest, "", "cannot deactivate the sole owner")
			return
		}
	}

	if err := srv.store.DeactivateOrgMember(ctx, orgID, userID); err != nil {
		slog.ErrorContext(ctx, "scim delete user: deactivate", "error", err)
		writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
		return
	}

	srv.scimAuditLog(r, orgID, scimConfigID, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "member",
		EntityID:   userID.String(),
		Success:    true,
		NewState:   map[string]any{"active": false},
		Metadata:   scimAuditMeta(scimConfigID),
	})
	srv.fireSCIMEvent(ctx, secure.EventSCIMUserDeprovisioned, &orgID)

	w.WriteHeader(http.StatusNoContent)
}

// checkSCIMMemberLimit checks whether the org has reached its tier member limit.
// Returns nil if within limits, non-nil error if limit exceeded.
func (srv *Server) checkSCIMMemberLimit(ctx context.Context, orgID uuid.UUID) error {
	tierName, overrides, err := srv.store.GetOrgTier(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: get org tier", "error", err)
		return nil // fail open — let provisioning proceed
	}
	resolver := &tier.Resolver{Tier: tierName, Overrides: overrides}
	limit := resolver.ResolveInt(tier.LimitMembers)
	if limit < 0 {
		return nil // unlimited
	}

	count, err := srv.store.CountActiveOrgMembers(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "scim: count active members", "error", err)
		return nil // fail open
	}

	if count >= limit {
		return fmt.Errorf("member limit %d reached", limit)
	}
	return nil
}

// getSCIMDefaultRole returns the default role from the SCIM config, or "viewer" if unavailable.
func (srv *Server) getSCIMDefaultRole(ctx context.Context, orgID uuid.UUID) string {
	cfg, err := srv.store.GetSCIMConfig(ctx, orgID)
	if err != nil || cfg == nil {
		return "viewer"
	}
	return cfg.DefaultRole
}

// scimAuditLog writes an audit log entry for SCIM operations.
// SCIM operations have no human actor (actor_id = nil).
func (srv *Server) scimAuditLog(r *http.Request, _, _ uuid.UUID, entry audit.Entry) {
	// Override: SCIM has no actor.
	noActor := uuid.Nil
	entry.ActorID = &noActor
	srv.auditLog(r, entry)
}
