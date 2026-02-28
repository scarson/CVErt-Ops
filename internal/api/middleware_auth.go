// ABOUTME: RequireAuthenticated middleware for JWT cookie or API key Bearer auth.
// ABOUTME: Injects userID and (for API keys) apiKeyRole into the request context.
package api

import (
	"context"
	"crypto/subtle"
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
	if err != nil || key == nil {
		return false
	}
	// Defense-in-depth: constant-time compare to prevent timing attacks.
	if subtle.ConstantTimeCompare([]byte(key.KeyHash), []byte(hash)) != 1 {
		return false
	}
	// Record last-used asynchronously — do not block the request path.
	go func() {
		bgCtx := context.WithoutCancel(r.Context())
		_ = srv.store.UpdateAPIKeyLastUsed(bgCtx, key.ID)
	}()
	ctx := context.WithValue(r.Context(), ctxUserID, key.CreatedByUserID)
	ctx = context.WithValue(ctx, ctxAPIKeyRole, key.Role)
	next.ServeHTTP(w, r.WithContext(ctx))
	return true
}
