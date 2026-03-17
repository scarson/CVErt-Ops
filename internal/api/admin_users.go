// ABOUTME: Site admin user management API handlers.
// ABOUTME: List, disable/enable, unlock, force-password-reset.
package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// adminUserCursor is the opaque cursor for admin user list pagination.
type adminUserCursor struct {
	T  time.Time `json:"t"`
	ID string    `json:"id"`
}

// adminListUsersHandler handles GET /api/v1/admin/users.
func (srv *Server) adminListUsersHandler(w http.ResponseWriter, r *http.Request) {
	limit, ok := parseLimitParam(w, r, 50, 200)
	if !ok {
		return
	}

	var afterTime *time.Time
	var afterID *uuid.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		var cur adminUserCursor
		if err := decodePageCursor(c, &cur); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterTime = &cur.T
		id, err := uuid.Parse(cur.ID)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid cursor")
			return
		}
		afterID = &id
	}

	users, err := srv.store.AdminListUsers(r.Context(), afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list users", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	var nextCursor string
	if len(users) > limit {
		users = users[:limit]
		last := users[len(users)-1]
		nextCursor = encodePageCursor(adminUserCursor{T: last.CreatedAt, ID: last.ID.String()})
	}

	writeList(w, users, nextCursor)
}

// adminDisableUserHandler handles POST /api/v1/admin/users/{user_id}/disable.
func (srv *Server) adminDisableUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	// Prevent admin from disabling their own account.
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	if callerID == userID {
		writeProblem(w, http.StatusBadRequest, "cannot disable your own account")
		return
	}

	// Check user exists first (the UPDATE with WHERE disabled_at IS NULL returns
	// no rows for both "not found" and "already disabled" — we need to distinguish).
	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin disable user: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	user, err := srv.store.AdminDisableUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Already disabled — idempotent. Re-fetch current state.
			user2, err2 := srv.store.AdminGetUserByID(r.Context(), userID)
			if err2 != nil {
				slog.ErrorContext(r.Context(), "admin disable user: re-fetch", "error", err2)
				writeProblem(w, http.StatusInternalServerError, "internal error")
				return
			}
			user = user2
		} else {
			slog.ErrorContext(r.Context(), "admin disable user", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled", "user_id": user.ID.String()})
}

// adminEnableUserHandler handles POST /api/v1/admin/users/{user_id}/enable.
func (srv *Server) adminEnableUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin enable user: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := srv.store.AdminEnableUser(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin enable user", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Already enabled — idempotent.
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled", "user_id": userID.String()})
}

// adminUnlockUserHandler handles POST /api/v1/admin/users/{user_id}/unlock.
func (srv *Server) adminUnlockUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin unlock user: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := srv.store.AdminUnlockUser(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin unlock user", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Not locked — idempotent.
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked", "user_id": userID.String()})
}

// adminResetPasswordHandler handles POST /api/v1/admin/users/{user_id}/reset-password.
func (srv *Server) adminResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid user_id")
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "user not found")
			return
		}
		slog.ErrorContext(r.Context(), "admin reset password: lookup", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := srv.store.AdminForcePasswordReset(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin reset password", "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Already flagged — idempotent.
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "password_reset_required", "user_id": userID.String()})
}
