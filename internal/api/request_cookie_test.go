// ABOUTME: Test helper that builds a cookie for an outgoing test request (sent as a Cookie header).
// ABOUTME: Holds the single gosec G124 suppression for request cookies in this package's tests.
package api

import "net/http"

// requestCookie returns a cookie for req.AddCookie or a cookie slice passed to a
// test request. Only Name and Value reach the server in a Cookie request header;
// Secure, HttpOnly and SameSite are Set-Cookie response attributes, so gosec G124
// does not apply here.
func requestCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value} //nolint:gosec // G124: request cookie; Secure/HttpOnly/SameSite are response-only attributes
}
