// ABOUTME: Org-level admin handlers for MFA reset and force password reset.
// ABOUTME: RBAC: owner targets members/admins; admin targets members; site admin targets anyone.
package api

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/secure"
)

// errPermissionDenied is returned by checkAdminMFAPermission when the caller
// lacks sufficient privileges. The HTTP error response is already written.
var errPermissionDenied = errors.New("permission denied")

// adminResetMFAHandler handles POST /api/v1/orgs/{org_id}/members/{user_id}/reset-mfa.
// Clears all MFA credentials, recovery codes, and challenges for the target user.
// Invalidates all sessions by incrementing token_version.
func (srv *Server) adminResetMFAHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	// Cannot reset your own MFA via admin endpoint — use self-service.
	if callerID == targetID {
		writeProblem(w, http.StatusBadRequest, "use self-service MFA management to modify your own MFA")
		return
	}

	// RBAC: check caller can act on target.
	if err := srv.checkAdminMFAPermission(w, r, orgID, callerID, callerRole, targetID); err != nil {
		return // response already written
	}

	// Delete all MFA state.
	if _, err := srv.store.DeleteAllMFACredentials(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin reset-mfa: delete credentials", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := srv.store.DeleteAllRecoveryCodes(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin reset-mfa: delete recovery codes", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := srv.store.DeleteAllUserChallenges(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin reset-mfa: delete challenges", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := srv.store.DeleteRememberDeviceTokens(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin reset-mfa: delete device tokens", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Invalidate all sessions.
	if _, err := srv.store.IncrementTokenVersion(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin reset-mfa: increment token version", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     secure.EventMFAAdminReset,
			Severity: secure.SeverityCritical,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
			OrgID:    &orgID,
			Details:  map[string]any{"target_user_id": targetID.String()},
		})
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     secure.EventMFAAdminReset,
		EntityType: "security_event",
		EntityID:   targetID.String(),
		Success:    true,
		Metadata:   map[string]any{"target_user_id": targetID.String()},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_reset", "user_id": targetID.String()})
}

// adminForcePasswordResetHandler handles POST /api/v1/orgs/{org_id}/members/{user_id}/force-password-reset.
// Sets force_password_reset=true, increments token_version, and deletes device tokens.
func (srv *Server) adminForcePasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	callerRole, ok := r.Context().Value(ctxRole).(Role)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if callerID == targetID {
		writeProblem(w, http.StatusBadRequest, "cannot force password reset on yourself")
		return
	}

	if err := srv.checkAdminMFAPermission(w, r, orgID, callerID, callerRole, targetID); err != nil {
		return // response already written
	}

	// Verify the target has a native identity (password hash).
	user, err := srv.store.GetUserByID(r.Context(), targetID)
	if err != nil || user == nil {
		slog.ErrorContext(r.Context(), "admin force-password-reset: get user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !user.PasswordHash.Valid {
		writeProblem(w, http.StatusBadRequest, "user has no native identity — cannot force password reset on OAuth-only account")
		return
	}

	// Set force_password_reset flag (idempotent).
	if _, err := srv.store.AdminForcePasswordReset(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin force-password-reset: set flag", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Invalidate sessions.
	if _, err := srv.store.IncrementTokenVersion(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin force-password-reset: increment token version", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Delete device tokens.
	if err := srv.store.DeleteRememberDeviceTokens(r.Context(), targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin force-password-reset: delete device tokens", "error", err)
		// Non-fatal — the important actions (flag + session invalidation) are done.
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     secure.EventAuthPasswordResetForced,
			Severity: secure.SeverityCritical,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
			OrgID:    &orgID,
			Details:  map[string]any{"target_user_id": targetID.String()},
		})
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     secure.EventAuthPasswordResetForced,
		EntityType: "security_event",
		EntityID:   targetID.String(),
		Success:    true,
		Metadata:   map[string]any{"target_user_id": targetID.String()},
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset_required", "user_id": targetID.String()})
}

// ── Per-member MFA requirements ───────────────────────────────────────────────

// adminRequireMFAHandler handles POST /api/v1/orgs/{org_id}/members/{user_id}/require-mfa.
// Adds a per-member MFA mandate. Idempotent.
func (srv *Server) adminRequireMFAHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	// Verify target is in the org.
	targetRole, err := srv.store.GetOrgMemberRole(r.Context(), orgID, targetID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin require-mfa: get role", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if targetRole == nil {
		writeProblem(w, http.StatusNotFound, "user not found in org")
		return
	}

	if err := srv.store.CreateMFARequirement(r.Context(), orgID, targetID, callerID); err != nil {
		slog.ErrorContext(r.Context(), "admin require-mfa: create", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     secure.EventMFAAdminRequireMember,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
			OrgID:    &orgID,
			Details:  map[string]any{"target_user_id": targetID.String()},
		})
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     secure.EventMFAAdminRequireMember,
		EntityType: "security_event",
		EntityID:   targetID.String(),
		Success:    true,
	})

	writeJSON(w, http.StatusCreated, map[string]string{"status": "mfa_required", "user_id": targetID.String()})
}

// adminUnrequireMFAHandler handles DELETE /api/v1/orgs/{org_id}/members/{user_id}/require-mfa.
// Removes the per-member MFA mandate. Idempotent.
func (srv *Server) adminUnrequireMFAHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	targetID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if err := srv.store.DeleteMFARequirement(r.Context(), orgID, targetID); err != nil {
		slog.ErrorContext(r.Context(), "admin unrequire-mfa: delete", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     secure.EventMFAAdminUnrequireMember,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
			OrgID:    &orgID,
			Details:  map[string]any{"target_user_id": targetID.String()},
		})
	}
	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     secure.EventMFAAdminUnrequireMember,
		EntityType: "security_event",
		EntityID:   targetID.String(),
		Success:    true,
	})

	w.WriteHeader(http.StatusNoContent)
}

// ── Org MFA settings ─────────────────────────────────────────────────────────

// updateOrgMFASettingsBody is the request body for PATCH /orgs/{org_id}/mfa-settings.
type updateOrgMFASettingsBody struct {
	MFARequiredAll           *bool  `json:"mfa_required_all,omitempty"`
	MFARememberDeviceAllowed *bool  `json:"mfa_remember_device_allowed,omitempty"`
	MFARememberDeviceDays    *int32 `json:"mfa_remember_device_days,omitempty"`
}

// adminUpdateOrgMFASettingsHandler handles PATCH /api/v1/orgs/{org_id}/mfa-settings.
// Owner-only. Updates MFA-related org settings.
func (srv *Server) adminUpdateOrgMFASettingsHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)

	var req updateOrgMFASettingsBody
	if decErr := decodeJSON(r, &req); decErr != nil {
		writeProblemWithErrors(w, http.StatusBadRequest, "invalid request body", decErr)
		return
	}

	// Read current org to merge pointer fields.
	existing, err := srv.store.GetOrgByID(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "update org mfa settings: read existing", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if existing == nil {
		writeProblem(w, http.StatusNotFound, "org not found")
		return
	}

	// Merge with existing values.
	requiredAll := existing.MfaRequiredAll
	if req.MFARequiredAll != nil {
		requiredAll = *req.MFARequiredAll
	}
	rememberAllowed := existing.MfaRememberDeviceAllowed
	if req.MFARememberDeviceAllowed != nil {
		rememberAllowed = *req.MFARememberDeviceAllowed
	}
	rememberDays := existing.MfaRememberDeviceDays
	if req.MFARememberDeviceDays != nil {
		days := *req.MFARememberDeviceDays
		if days < 7 || days > 90 {
			writeProblem(w, http.StatusBadRequest, "mfa_remember_device_days must be between 7 and 90")
			return
		}
		rememberDays = days
	}

	org, err := srv.store.UpdateOrgMFASettings(r.Context(), orgID, requiredAll, rememberAllowed, rememberDays)
	if err != nil {
		slog.ErrorContext(r.Context(), "update org mfa settings", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if org == nil {
		writeProblem(w, http.StatusNotFound, "org not found")
		return
	}

	// Emit event if mfa_required_all changed.
	if srv.eventWriter != nil && org.MfaRequiredAll != existing.MfaRequiredAll {
		evType := secure.EventMFAOrgRequireAllEnabled
		severity := secure.SeverityInfo
		if !org.MfaRequiredAll {
			evType = secure.EventMFAOrgRequireAllDisabled
			severity = secure.SeverityWarning
		}
		srv.eventWriter.Write(r.Context(), secure.Event{
			Type:     evType,
			Severity: severity,
			ActorIP:  clientIP(r.Context()),
			UserID:   &callerID,
			OrgID:    &orgID,
		})
	}

	srv.auditLog(r, audit.Entry{
		OrgID:      orgID,
		Action:     "update",
		EntityType: "org_mfa_settings",
		EntityID:   orgID.String(),
		Success:    true,
		NewState: map[string]any{
			"mfa_required_all":            org.MfaRequiredAll,
			"mfa_remember_device_allowed": org.MfaRememberDeviceAllowed,
			"mfa_remember_device_days":    org.MfaRememberDeviceDays,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"mfa_required_all":            org.MfaRequiredAll,
		"mfa_remember_device_allowed": org.MfaRememberDeviceAllowed,
		"mfa_remember_device_days":    org.MfaRememberDeviceDays,
	})
}

// checkAdminMFAPermission enforces the RBAC hierarchy for admin MFA/password actions.
// Owner can target members/admins. Admin can target members only.
// Site admin can target anyone including owners.
// Writes an error response and returns a non-nil error if permission is denied.
func (srv *Server) checkAdminMFAPermission(w http.ResponseWriter, r *http.Request, orgID, callerID uuid.UUID, callerRole Role, targetID uuid.UUID) error {
	// Look up target's role in the org.
	targetRoleStr, err := srv.store.GetOrgMemberRole(r.Context(), orgID, targetID)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin mfa: get target role", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return err
	}
	if targetRoleStr == nil {
		writeProblem(w, http.StatusNotFound, "user not found in org")
		return errPermissionDenied
	}

	targetRole := parseRole(*targetRoleStr)

	// Site admin bypass — can target anyone.
	isSiteAdmin, saErr := srv.store.IsSiteAdmin(r.Context(), callerID)
	if saErr != nil {
		slog.ErrorContext(r.Context(), "admin mfa: check site admin", "error", saErr)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return saErr
	}
	if isSiteAdmin {
		return nil
	}

	// Owner can target admins and below.
	if callerRole == RoleOwner && targetRole < RoleOwner {
		return nil
	}

	// Admin can target members and below.
	if callerRole == RoleAdmin && targetRole < RoleAdmin {
		return nil
	}

	writeProblem(w, http.StatusForbidden, "insufficient permissions")
	return errPermissionDenied
}
