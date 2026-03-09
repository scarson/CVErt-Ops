// ABOUTME: CORS middleware configuration for cross-origin frontend requests.
// ABOUTME: Returns allowed origins from config, with dev defaults for localhost dev servers.
package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/cors"
)

// corsMiddleware returns a configured CORS middleware, or nil if CORS should be disabled.
// In development with no explicit config, defaults to localhost dev server origins.
// In production with no config, returns nil (CORS disabled).
func (srv *Server) corsMiddleware() func(http.Handler) http.Handler {
	origins := srv.corsOrigins()
	if len(origins) == 0 {
		return nil
	}
	return cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Requested-By"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	})
}

// corsOrigins returns the list of allowed origins for CORS.
// Priority: explicit config > dev defaults > none.
func (srv *Server) corsOrigins() []string {
	if srv.cfg.CORSAllowedOrigins != "" {
		parts := strings.Split(srv.cfg.CORSAllowedOrigins, ",")
		origins := make([]string, 0, len(parts))
		for _, p := range parts {
			if o := strings.TrimSpace(p); o != "" {
				origins = append(origins, o)
			}
		}
		return origins
	}

	// Dev defaults: Vite (5173) and common alt dev server (3000).
	if srv.cfg.IsDevelopment() {
		return []string{
			"http://localhost:3000",
			"http://localhost:5173",
		}
	}

	return nil
}
