// ABOUTME: Generic OIDC SSO login flow: init redirect and callback handler.
// ABOUTME: Dynamically loads SSO connection config from DB; matches on provider identity.
package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/crypto"
)

// oidcClaims holds the subset of OIDC ID token claims used for SSO.
type oidcClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Nonce string `json:"nonce"`
}

// oidcLoginHandler handles GET /api/v1/auth/oidc/{connection_id}/login.
// Loads the SSO connection from DB, builds an OIDC provider, and redirects to the IdP.
func (srv *Server) oidcLoginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connID, err := uuid.Parse(chi.URLParam(r, "connection_id"))
	if err != nil {
		http.Error(w, "invalid connection_id", http.StatusBadRequest)
		return
	}

	conn, err := srv.store.GetSSOConnectionByID(ctx, connID)
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: get connection", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conn == nil {
		http.Error(w, "SSO connection not found", http.StatusNotFound)
		return
	}
	if !conn.Enabled {
		http.Error(w, "SSO connection is disabled", http.StatusForbidden)
		return
	}

	// Build OIDC provider from issuer URL.
	provider, err := oidc.NewProvider(ctx, conn.IssuerUrl)
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: new provider", "error", err, "issuer", conn.IssuerUrl)
		http.Error(w, "SSO configuration error", http.StatusBadGateway)
		return
	}

	// Decrypt client secret.
	key, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: encryption key", "error", err)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}
	secret, err := crypto.Decrypt(key, conn.ClientSecretEnc)
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: decrypt secret", "error", err)
		http.Error(w, "SSO configuration error", http.StatusInternalServerError)
		return
	}

	oauthCfg := &oauth2.Config{ //nolint:exhaustruct // optional fields
		ClientID:     conn.ClientID,
		ClientSecret: string(secret),
		RedirectURL:  srv.cfg.ExternalURL + "/api/v1/auth/oidc/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       conn.Scopes,
	}

	// State encodes the connection_id so the callback can identify the SSO connection.
	randomState, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := randomState + "_" + connID.String()

	nonce, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(ctx, "oidc login: generate nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	srv.setStateCookie(w, state)
	srv.setNonceCookie(w, nonce)
	authURL := oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcCallbackHandler handles GET /api/v1/auth/oidc/callback.
// Validates state, verifies the ID token, matches by provider identity, and issues JWT tokens.
// Unlike Google/GitHub OAuth, SSO does NOT auto-create users — returns 403 if no linked identity.
func (srv *Server) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Validate CSRF state and extract connection_id.
	state := r.URL.Query().Get("state")
	if err := srv.validateStateCookie(r, w, state); err != nil {
		http.Error(w, "invalid state: "+err.Error(), http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(state, "_", 2)
	if len(parts) != 2 {
		http.Error(w, "malformed state", http.StatusBadRequest)
		return
	}
	connID, err := uuid.Parse(parts[1])
	if err != nil {
		http.Error(w, "invalid connection_id in state", http.StatusBadRequest)
		return
	}

	// 2. Load SSO connection.
	conn, err := srv.store.GetSSOConnectionByID(ctx, connID)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: get connection", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conn == nil {
		http.Error(w, "SSO connection not found", http.StatusNotFound)
		return
	}
	if !conn.Enabled {
		http.Error(w, "SSO connection is disabled", http.StatusForbidden)
		return
	}

	// 3. Build OIDC provider + oauth2 config.
	provider, err := oidc.NewProvider(ctx, conn.IssuerUrl)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: new provider", "error", err)
		http.Error(w, "SSO configuration error", http.StatusBadGateway)
		return
	}
	key, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: encryption key", "error", err)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}
	secret, err := crypto.Decrypt(key, conn.ClientSecretEnc)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: decrypt secret", "error", err)
		http.Error(w, "SSO configuration error", http.StatusInternalServerError)
		return
	}
	oauthCfg := &oauth2.Config{ //nolint:exhaustruct // optional fields
		ClientID:     conn.ClientID,
		ClientSecret: string(secret),
		RedirectURL:  srv.cfg.ExternalURL + "/api/v1/auth/oidc/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       conn.Scopes,
	}

	// 4. Exchange authorization code for tokens.
	code := r.URL.Query().Get("code")
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: exchange code", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	// 5. Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		slog.ErrorContext(ctx, "oidc callback: missing id_token in token response")
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: conn.ClientID}) //nolint:exhaustruct // only ClientID needed
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: verify id token", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	// 6. Extract claims.
	var claims oidcClaims
	if err := idToken.Claims(&claims); err != nil {
		slog.ErrorContext(ctx, "oidc callback: extract claims", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	if claims.Sub == "" {
		http.Error(w, "missing sub in ID token", http.StatusBadRequest)
		return
	}

	// 7. Validate nonce.
	storedNonce, err := srv.validateNonceCookie(r, w)
	if err != nil {
		http.Error(w, "invalid nonce: "+err.Error(), http.StatusBadRequest)
		return
	}
	if storedNonce != claims.Nonce {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	// 8. Look up user by provider identity: "oidc:{connection_id}" + sub.
	// SSO does NOT auto-create users — admin must link identities first.
	providerKey := "oidc:" + connID.String()
	user, err := srv.store.GetUserByProviderID(ctx, providerKey, claims.Sub)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: get user", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "no linked identity — ask your admin to link your account", http.StatusForbidden)
		return
	}

	// 9. Issue JWT access + refresh tokens.
	jwtSecret := []byte(srv.cfg.JWTSecret)
	jti := uuid.New()
	accessToken, err := auth.IssueAccessToken(jwtSecret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: issue access token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshTokenStr, err := auth.IssueRefreshToken(jwtSecret, user.ID, int(user.TokenVersion), jti, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: issue refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := srv.store.CreateRefreshToken(ctx, jti, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "oidc callback: create refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 10. Set auth cookies and respond.
	for _, cookieStr := range authCookies(accessToken, refreshTokenStr, srv.cfg.CookieSecure) {
		w.Header().Add("Set-Cookie", cookieStr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": user.ID.String()})
}
