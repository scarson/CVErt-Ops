// ABOUTME: RequireAuthenticated middleware for JWT cookie or API key Bearer auth.
// ABOUTME: Injects userID and (for API keys) apiKeyRole into the request context.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/scarson/cvert-ops/internal/auth"
)

// RequireAuthenticated returns a middleware that requires a valid JWT access-token
// cookie or an API key Bearer token. On success it injects ctxUserID (and for API
// keys also ctxAPIKeyRole) into the request context.
func (srv *Server) RequireAuthenticated() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API key first (Authorization: Bearer <key>).
			if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
				rawKey := strings.TrimPrefix(authHeader, "Bearer ")
				if srv.tryAPIKeyAuth(r, rawKey, w, next) {
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Try JWT access-token cookie.
			cookie, err := r.Cookie("access_token")
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			// Reject disabled users and enforce force_password_reset.
			authStatus, err := srv.store.GetUserAuthStatus(r.Context(), claims.UserID)
			if err != nil {
				slog.ErrorContext(r.Context(), "auth: check user status", "user_id", claims.UserID, "error", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if !authStatus.Enabled {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if authStatus.ForcePasswordReset {
				path := r.URL.Path
				allowed := strings.HasSuffix(path, "/auth/change-password") ||
					strings.HasSuffix(path, "/auth/me") ||
					strings.HasSuffix(path, "/auth/logout")
				if !allowed {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusForbidden)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"title":  "Password change required",
						"detail": "Your password must be changed before continuing",
						"type":   "password_change_required",
					})
					return
				}
			}
			ctx := context.WithValue(r.Context(), ctxUserID, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// tryAPIKeyAuth validates rawKey against the database and, on success, calls next
// with the user/role injected into context. Returns false if the key is invalid.
func (srv *Server) tryAPIKeyAuth(r *http.Request, rawKey string, w http.ResponseWriter, next http.Handler) bool {
	hash := auth.HashAPIKey(rawKey)
	key, err := srv.store.LookupAPIKey(r.Context(), hash)
	if err != nil {
		slog.ErrorContext(r.Context(), "api key auth: database error", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true // response sent
	}
	if key == nil {
		return false
	}
	// Defense-in-depth: constant-time compare to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(key.KeyHash), []byte(hash)) != 1 {
		return false
	}
	// API key auth checks enabled only — API keys cannot change passwords,
	// so force_password_reset does not apply.
	enabled, err := srv.store.IsUserEnabled(r.Context(), key.CreatedByUserID)
	if err != nil {
		slog.ErrorContext(r.Context(), "api key auth: check user enabled", "user_id", key.CreatedByUserID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return true // response sent
	}
	if !enabled {
		return false
	}
	// Record last-used asynchronously — do not block the request path.
	go func() {
		bgCtx := context.WithoutCancel(r.Context())
		_ = srv.store.UpdateAPIKeyLastUsed(bgCtx, key.ID)
	}()
	ctx := context.WithValue(r.Context(), ctxUserID, key.CreatedByUserID)
	ctx = context.WithValue(ctx, ctxAPIKeyRole, key.Role)
	ctx = context.WithValue(ctx, ctxAPIKeyOrgID, key.OrgID)
	next.ServeHTTP(w, r.WithContext(ctx))
	return true
}
