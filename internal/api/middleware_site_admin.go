// ABOUTME: Middleware that restricts access to site-admin-only routes.
// ABOUTME: Requires RequireAuthenticated to run first to populate ctxUserID.
package api

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

// RequireSiteAdmin returns middleware that rejects requests from non-site-admin users.
// It expects ctxUserID to be set by RequireAuthenticated upstream.
func (srv *Server) RequireSiteAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			isAdmin, err := srv.store.IsSiteAdmin(r.Context(), userID)
			if err != nil {
				slog.ErrorContext(r.Context(), "check site admin", "user_id", userID, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !isAdmin {
				http.Error(w, "forbidden: site admin required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
