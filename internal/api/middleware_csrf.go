// ABOUTME: CSRF protection middleware using the custom-header pattern.
// ABOUTME: Cookie-authenticated state-changing requests must include X-Requested-By: CVErt-Ops.
package api

import (
	"net/http"
)

// csrfProtect is a middleware that rejects state-changing requests authenticated
// via cookie when the X-Requested-By: CVErt-Ops header is absent.
//
// Rationale: browsers automatically attach cookies (including HttpOnly ones) to
// same-site and cross-subdomain requests. A custom request header cannot be set
// by a plain HTML form or cross-origin fetch without a CORS preflight that the
// server would reject. This makes the header an unforgeable proof of intent for
// browser-initiated requests.
//
// Exemptions:
//   - Safe methods (GET, HEAD, OPTIONS, TRACE) carry no state-change risk.
//   - Requests without an access_token cookie use Bearer token auth and are not
//     susceptible to CSRF (the browser has no token to attach automatically).
func csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}

		if _, err := r.Cookie("access_token"); err != nil {
			// No cookie — Bearer token or unauthenticated; exempt from CSRF check.
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("X-Requested-By") != "CVErt-Ops" {
			http.Error(w, "CSRF check failed: X-Requested-By header required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
