// ABOUTME: OAuth helper functions: state/nonce generation, cookie management.
// ABOUTME: Used by GitHub OAuth2 and Google OIDC flow handlers.
package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
)

// generateOAuthState generates 32 random bytes as a hex string for the OAuth state param.
func generateOAuthState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// setStateCookie sets the oauth_state HttpOnly cookie with a 5-minute expiry.
// SameSite=Lax is REQUIRED (not Strict) — the callback is a cross-site redirect.
func (srv *Server) setStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   srv.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode, // NOT Strict — cross-site callback
		MaxAge:   300,                  // 5 minutes
		Path:     "/",
	})
}

// validateStateCookie reads and deletes the oauth_state cookie, returning an error
// if the cookie is missing or its value doesn't match the stateParam from the query string.
func (srv *Server) validateStateCookie(r *http.Request, w http.ResponseWriter, stateParam string) error {
	cookie, err := r.Cookie("oauth_state")
	if err != nil {
		return errors.New("missing oauth_state cookie")
	}
	// Delete the cookie immediately (one-time use).
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		HttpOnly: true,
		Secure:   srv.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
	})
	if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(stateParam)) != 1 {
		return errors.New("oauth_state mismatch")
	}
	return nil
}

// setNonceCookie sets the oidc_nonce HttpOnly cookie for Google OIDC nonce verification.
// SameSite=Lax required — same cross-site redirect reasoning as state.
func (srv *Server) setNonceCookie(w http.ResponseWriter, nonce string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    nonce,
		HttpOnly: true,
		Secure:   srv.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300, // 5 minutes
		Path:     "/",
	})
}

// validateNonceCookie reads and deletes the oidc_nonce cookie, returning its value.
// Returns an error if the cookie is missing.
func (srv *Server) validateNonceCookie(r *http.Request, w http.ResponseWriter) (string, error) {
	cookie, err := r.Cookie("oidc_nonce")
	if err != nil {
		return "", errors.New("missing oidc_nonce cookie")
	}
	// Delete the cookie immediately (one-time use).
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_nonce",
		Value:    "",
		HttpOnly: true,
		Secure:   srv.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Path:     "/",
	})
	return cookie.Value, nil
}
