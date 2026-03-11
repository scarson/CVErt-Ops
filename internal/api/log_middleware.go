// ABOUTME: Middleware that injects a request-scoped slog logger into the context.
// ABOUTME: Enriches the logger with request_id from chi's RequestID middleware.
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"

	logpkg "github.com/scarson/cvert-ops/internal/log"
)

// contextLoggerMiddleware creates an enriched slog logger with request_id
// and stores it in the request context via log.WithLogger.
func contextLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if reqID := middleware.GetReqID(ctx); reqID != "" {
			ctx = logpkg.Enrich(ctx, "request_id", reqID)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
