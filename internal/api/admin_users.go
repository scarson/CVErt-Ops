// ABOUTME: Site admin user management API handlers.
// ABOUTME: List, disable/enable, unlock, force-password-reset.
package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// adminListUsersHandler handles GET /api/v1/admin/users.
func (srv *Server) adminListUsersHandler(w http.ResponseWriter, r *http.Request) {
	limit, afterTime, afterID, ok := parseKeysetParams(w, r)
	if !ok {
		return
	}

	users, err := srv.store.AdminListUsers(r.Context(), afterTime, afterID, limit+1)
	if err != nil {
		slog.ErrorContext(r.Context(), "admin list users", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit]
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"items":    users,
		"has_more": hasMore,
	}); err != nil {
		slog.ErrorContext(r.Context(), "admin list users: encode", "error", err)
	}
}

// adminDisableUserHandler handles POST /api/v1/admin/users/{user_id}/disable.
func (srv *Server) adminDisableUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	// Prevent admin from disabling their own account.
	callerID, _ := r.Context().Value(ctxUserID).(uuid.UUID)
	if callerID == userID {
		http.Error(w, "cannot disable your own account", http.StatusBadRequest)
		return
	}

	// Check user exists first (the UPDATE with WHERE disabled_at IS NULL returns
	// no rows for both "not found" and "already disabled" — we need to distinguish).
	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin disable user: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, err := srv.store.AdminDisableUser(r.Context(), userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Already disabled — idempotent. Re-fetch current state.
			user2, err2 := srv.store.AdminGetUserByID(r.Context(), userID)
			if err2 != nil {
				slog.ErrorContext(r.Context(), "admin disable user: re-fetch", "error", err2)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			user = user2
		} else {
			slog.ErrorContext(r.Context(), "admin disable user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "disabled", "user_id": user.ID.String()}); err != nil {
		slog.ErrorContext(r.Context(), "admin disable user: encode", "error", err)
	}
}

// adminEnableUserHandler handles POST /api/v1/admin/users/{user_id}/enable.
func (srv *Server) adminEnableUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin enable user: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := srv.store.AdminEnableUser(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin enable user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Already enabled — idempotent.
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "enabled", "user_id": userID.String()}); err != nil {
		slog.ErrorContext(r.Context(), "admin enable user: encode", "error", err)
	}
}

// adminUnlockUserHandler handles POST /api/v1/admin/users/{user_id}/unlock.
func (srv *Server) adminUnlockUserHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin unlock user: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := srv.store.AdminUnlockUser(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin unlock user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Not locked — idempotent.
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "unlocked", "user_id": userID.String()}); err != nil {
		slog.ErrorContext(r.Context(), "admin unlock user: encode", "error", err)
	}
}

// adminResetPasswordHandler handles POST /api/v1/admin/users/{user_id}/reset-password.
func (srv *Server) adminResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "user_id"))
	if err != nil {
		http.Error(w, "invalid user_id", http.StatusBadRequest)
		return
	}

	if _, err := srv.store.AdminGetUserByID(r.Context(), userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		slog.ErrorContext(r.Context(), "admin reset password: lookup", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if _, err := srv.store.AdminForcePasswordReset(r.Context(), userID); err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.ErrorContext(r.Context(), "admin reset password", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Already flagged — idempotent.
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "password_reset_required", "user_id": userID.String()}); err != nil {
		slog.ErrorContext(r.Context(), "admin reset password: encode", "error", err)
	}
}
