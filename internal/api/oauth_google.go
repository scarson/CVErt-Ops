// ABOUTME: Google OIDC login flow: init redirect and callback handler.
// ABOUTME: Matches on Google account sub claim (never email) per PLAN.md §7.2.
package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/scarson/cvert-ops/internal/auth"
)

// googleClaims holds the subset of Google ID token claims we use.
type googleClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Nonce         string `json:"nonce"`
}

// googleInitHandler handles GET /api/v1/auth/oauth/google.
// Generates state + nonce, sets cookies, and redirects to Google's authorize URL.
func (srv *Server) googleInitHandler(w http.ResponseWriter, r *http.Request) {
	if srv.googleOIDC == nil {
		http.Error(w, "Google OIDC not configured", http.StatusNotImplemented)
		return
	}
	state, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(r.Context(), "google oidc init: generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := generateOAuthState() // reuses the same CSPRNG helper for nonce
	if err != nil {
		slog.ErrorContext(r.Context(), "google oidc init: generate nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	srv.setStateCookie(w, state)
	srv.setNonceCookie(w, nonce)
	authURL := srv.googleOAuth.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// googleCallbackHandler handles GET /api/v1/auth/oauth/google/callback.
// Validates state + nonce, verifies the ID token, upserts the identity,
// and issues JWT tokens as HttpOnly cookies.
func (srv *Server) googleCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Validate CSRF state.
	state := r.URL.Query().Get("state")
	if err := srv.validateStateCookie(r, w, state); err != nil {
		http.Error(w, "invalid state: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Exchange authorization code for tokens.
	code := r.URL.Query().Get("code")
	token, err := srv.googleOAuth.Exchange(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "google oidc: exchange code", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	// 3. Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		slog.ErrorContext(ctx, "google oidc: missing id_token in token response")
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}
	verifier := srv.googleOIDC.Verifier(&oidc.Config{ClientID: srv.googleOAuth.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.ErrorContext(ctx, "google oidc: verify id token", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	// 4. Extract claims.
	var claims googleClaims
	if err := idToken.Claims(&claims); err != nil {
		slog.ErrorContext(ctx, "google oidc: extract claims", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	if claims.Sub == "" {
		http.Error(w, "missing sub in ID token", http.StatusBadRequest)
		return
	}
	if !claims.EmailVerified {
		http.Error(w, "email not verified on Google account", http.StatusBadRequest)
		return
	}

	// 5. Validate nonce (required per PLAN.md §7.2).
	storedNonce, err := srv.validateNonceCookie(r, w)
	if err != nil {
		http.Error(w, "invalid nonce: "+err.Error(), http.StatusBadRequest)
		return
	}
	if storedNonce != claims.Nonce {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	// 6. Look up user by Google sub — NEVER by email (PLAN.md §7.2).
	user, err := srv.store.GetUserByProviderID(ctx, "google", claims.Sub)
	if err != nil {
		slog.ErrorContext(ctx, "google oidc: get user by provider id", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		// New user — create account (no password; Google-only auth).
		displayName := claims.Name
		if displayName == "" {
			displayName = claims.Email
		}
		user, err = srv.store.CreateUser(ctx, claims.Email, displayName, "", 0)
		if err != nil {
			slog.ErrorContext(ctx, "google oidc: create user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Bootstrap a default org for the first user (mirrors native register flow).
		if _, err := srv.store.BootstrapFirstUserOrg(ctx, user.ID, displayName+"'s Organization"); err != nil {
			slog.ErrorContext(ctx, "google oidc: bootstrap org", "error", err)
			// Non-fatal: user was created, proceed with login.
		}
	}

	// 7. Upsert identity to keep email current (Google email may change).
	if err := srv.store.UpsertUserIdentity(ctx, user.ID, "google", claims.Sub, claims.Email); err != nil {
		slog.ErrorContext(ctx, "google oidc: upsert identity", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 8. Issue JWT access + refresh tokens.
	secret := []byte(srv.cfg.JWTSecret)
	jti := uuid.New()
	accessToken, err := auth.IssueAccessToken(secret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "google oidc: issue access token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshTokenStr, err := auth.IssueRefreshToken(secret, user.ID, int(user.TokenVersion), jti, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "google oidc: issue refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := srv.store.CreateRefreshToken(ctx, jti, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "google oidc: create refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 9. Set auth cookies and respond.
	for _, cookieStr := range authCookies(accessToken, refreshTokenStr, srv.cfg.CookieSecure) {
		w.Header().Add("Set-Cookie", cookieStr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": user.ID.String()})
}
