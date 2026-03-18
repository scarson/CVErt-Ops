// ABOUTME: Cache-Control middleware for authenticated responses.
// ABOUTME: Prevents browsers and proxies from caching sensitive API responses.
package api

import "net/http"

// noCacheMiddleware sets Cache-Control: no-store on all responses.
// Applied to authenticated routes to prevent caching of sensitive data
// in browser caches, shared proxies, or CDN layers.
func noCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
