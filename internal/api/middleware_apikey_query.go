// ABOUTME: Middleware that rejects requests with API keys or secrets in query parameters.
// ABOUTME: Prevents accidental credential leakage in URLs, server logs, and browser history.
package api

import (
	"net/http"
	"strings"
)

// sensitiveQueryParams lists query parameter names that may contain API keys or secrets.
// These must never appear in URLs — use the Authorization header instead.
var sensitiveQueryParams = []string{
	"api_key",
	"apikey",
	"api-key",
	"token",
	"access_token",
	"key",
	"secret",
	"bearer",
}

// hasNonEmptyValue reports whether any element in vals is non-empty.
func hasNonEmptyValue(vals []string) bool {
	for _, v := range vals {
		if v != "" {
			return true
		}
	}
	return false
}

// rejectAPIKeyQueryParams returns middleware that blocks requests containing
// API keys or secrets in query parameters. Credentials in URLs leak to server
// logs, browser history, proxy logs, and Referer headers.
func rejectAPIKeyQueryParams(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		for param, values := range query {
			lower := strings.ToLower(param)
			for _, sensitive := range sensitiveQueryParams {
				if lower == sensitive && hasNonEmptyValue(values) {
					writeProblem(w, http.StatusBadRequest, "API keys must not be sent in query parameters; use the Authorization header")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}
