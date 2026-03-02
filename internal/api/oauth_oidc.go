// ABOUTME: Generic OIDC SSO login and identity linking flows.
// ABOUTME: Dynamically loads SSO connection config from DB; matches on provider identity.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/store"
)

// oidcClaims holds the subset of OIDC ID token claims used for SSO.
type oidcClaims struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Nonce string `json:"nonce"`
}

// getOIDCProvider returns a cached OIDC provider for the given issuer URL,
// creating one via discovery if not yet cached.
func (srv *Server) getOIDCProvider(ctx context.Context, issuerURL string) (*oidc.Provider, error) {
	if cached, ok := srv.oidcProviders.Load(issuerURL); ok {
		return cached.(*oidc.Provider), nil
	}
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}
	actual, _ := srv.oidcProviders.LoadOrStore(issuerURL, provider)
	return actual.(*oidc.Provider), nil
}

// oidcBuildOAuthConfig builds the OIDC provider and oauth2.Config for an SSO connection.
func (srv *Server) oidcBuildOAuthConfig(ctx context.Context, conn *store.SSOConnectionRow, redirectURL string) (*oauth2.Config, *oidc.Provider, error) {
	provider, err := srv.getOIDCProvider(ctx, conn.IssuerUrl)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc provider: %w", err)
	}
	key, err := srv.ssoEncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("encryption key: %w", err)
	}
	secret, err := crypto.Decrypt(key, conn.ClientSecretEnc)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt secret: %w", err)
	}
	oauthCfg := &oauth2.Config{ //nolint:exhaustruct // optional fields
		ClientID:     conn.ClientID,
		ClientSecret: string(secret),
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       conn.Scopes,
	}
	return oauthCfg, provider, nil
}

// oidcInitRedirect generates state + nonce, sets cookies, and redirects to the IdP.
func (srv *Server) oidcInitRedirect(w http.ResponseWriter, r *http.Request, conn *store.SSOConnectionRow, redirectURL string) {
	ctx := r.Context()

	oauthCfg, _, err := srv.oidcBuildOAuthConfig(ctx, conn, redirectURL)
	if err != nil {
		slog.ErrorContext(ctx, "oidc init: build config", "error", err)
		http.Error(w, "SSO configuration error", http.StatusInternalServerError)
		return
	}

	// State encodes the connection_id so the callback can identify the SSO connection.
	randomState, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(ctx, "oidc init: generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := randomState + "_" + conn.ID.String() // Format: {hex}_{uuid} — hex has no underscores

	nonce, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(ctx, "oidc init: generate nonce", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	srv.setStateCookie(w, state)
	srv.setNonceCookie(w, nonce)
	authURL := oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcVerifyCallback validates state/nonce, loads the SSO connection, exchanges the
// authorization code, and verifies the ID token. Returns the connection ID and claims.
// On failure writes an error response and returns ok=false.
func (srv *Server) oidcVerifyCallback(w http.ResponseWriter, r *http.Request, redirectURL string) (connID uuid.UUID, claims *oidcClaims, ok bool) {
	ctx := r.Context()

	// 1. Validate CSRF state and extract connection_id.
	state := r.URL.Query().Get("state")
	if err := srv.validateStateCookie(r, w, state); err != nil {
		http.Error(w, "invalid state: "+err.Error(), http.StatusBadRequest)
		return uuid.Nil, nil, false
	}
	parts := strings.SplitN(state, "_", 2)
	if len(parts) != 2 {
		http.Error(w, "malformed state", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}
	cID, err := uuid.Parse(parts[1])
	if err != nil {
		http.Error(w, "invalid connection_id in state", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	// 2. Load SSO connection.
	conn, err := srv.store.GetSSOConnectionByID(ctx, cID)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: get connection", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return uuid.Nil, nil, false
	}
	if conn == nil {
		http.Error(w, "SSO connection not found", http.StatusNotFound)
		return uuid.Nil, nil, false
	}
	if !conn.Enabled {
		http.Error(w, "SSO connection is disabled", http.StatusForbidden)
		return uuid.Nil, nil, false
	}

	// 3. Build OIDC provider + oauth2 config.
	oauthCfg, provider, err := srv.oidcBuildOAuthConfig(ctx, conn, redirectURL)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: build config", "error", err)
		http.Error(w, "SSO configuration error", http.StatusInternalServerError)
		return uuid.Nil, nil, false
	}

	// 4. Exchange authorization code for tokens.
	code := r.URL.Query().Get("code")
	token, err := oauthCfg.Exchange(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: exchange code", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	// 5. Extract and verify the ID token.
	rawIDToken, isStr := token.Extra("id_token").(string)
	if !isStr || rawIDToken == "" {
		slog.ErrorContext(ctx, "oidc callback: missing id_token in token response")
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: conn.ClientID}) //nolint:exhaustruct // only ClientID needed
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.ErrorContext(ctx, "oidc callback: verify id token", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	// 6. Extract claims.
	var c oidcClaims
	if err := idToken.Claims(&c); err != nil {
		slog.ErrorContext(ctx, "oidc callback: extract claims", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return uuid.Nil, nil, false
	}
	if c.Sub == "" {
		http.Error(w, "missing sub in ID token", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	// 7. Validate nonce.
	storedNonce, err := srv.validateNonceCookie(r, w)
	if err != nil {
		http.Error(w, "invalid nonce: "+err.Error(), http.StatusBadRequest)
		return uuid.Nil, nil, false
	}
	if storedNonce != c.Nonce {
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}

	return cID, &c, true
}

// ── Login flow ──────────────────────────────────────────────────────────────

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

	srv.oidcInitRedirect(w, r, conn, srv.cfg.ExternalURL+"/api/v1/auth/oidc/callback")
}

// oidcCallbackHandler handles GET /api/v1/auth/oidc/callback.
// Validates state, verifies the ID token, matches by provider identity, and issues JWT tokens.
// Unlike Google/GitHub OAuth, SSO does NOT auto-create users — returns 403 if no linked identity.
func (srv *Server) oidcCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connID, claims, ok := srv.oidcVerifyCallback(w, r, srv.cfg.ExternalURL+"/api/v1/auth/oidc/callback")
	if !ok {
		return
	}

	// Look up user by provider identity: "oidc:{connection_id}" + sub.
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

	// Issue JWT access + refresh tokens.
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

	for _, cookieStr := range authCookies(accessToken, refreshTokenStr, srv.cfg.CookieSecure) {
		w.Header().Add("Set-Cookie", cookieStr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": user.ID.String()})
}

// ── Identity linking flow ───────────────────────────────────────────────────

// oidcLinkInitHandler handles GET /api/v1/orgs/{org_id}/sso/link.
// Requires authenticated user with org membership. Loads the org's SSO connection
// and redirects to the IdP with the link-callback URL.
func (srv *Server) oidcLinkInitHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := ctx.Value(ctxOrgID).(uuid.UUID) //nolint:errcheck,forcetypeassert // set by RBAC middleware

	conn, err := srv.store.GetSSOConnection(ctx, orgID)
	if err != nil {
		slog.ErrorContext(ctx, "oidc link init: get connection", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if conn == nil {
		http.Error(w, "no SSO connection configured for this organization", http.StatusNotFound)
		return
	}
	if !conn.Enabled {
		http.Error(w, "SSO connection is disabled", http.StatusForbidden)
		return
	}

	srv.oidcInitRedirect(w, r, conn, srv.cfg.ExternalURL+"/api/v1/auth/oidc/link-callback")
}

// oidcLinkCallbackHandler handles GET /api/v1/auth/oidc/link-callback.
// Validates the OIDC token, reads the authenticated user from the JWT cookie,
// and creates a user_identities record linking the user to their SSO identity.
// Returns 409 if the provider identity is already linked to a different user.
func (srv *Server) oidcLinkCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connID, claims, ok := srv.oidcVerifyCallback(w, r, srv.cfg.ExternalURL+"/api/v1/auth/oidc/link-callback")
	if !ok {
		return
	}

	// Read authenticated user from JWT cookie.
	cookie, err := r.Cookie("access_token")
	if err != nil {
		http.Error(w, "unauthorized — must be logged in to link identity", http.StatusUnauthorized)
		return
	}
	jwtClaims, err := auth.ParseAccessToken(cookie.Value, []byte(srv.cfg.JWTSecret))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	userID := jwtClaims.UserID

	// Check if this provider identity is already linked to a different user.
	providerKey := "oidc:" + connID.String()
	existingUser, err := srv.store.GetUserByProviderID(ctx, providerKey, claims.Sub)
	if err != nil {
		slog.ErrorContext(ctx, "oidc link: check existing", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil && existingUser.ID != userID {
		http.Error(w, "identity already linked to another user", http.StatusConflict)
		return
	}

	// Create/update identity link.
	if err := srv.store.UpsertUserIdentity(ctx, userID, providerKey, claims.Sub, claims.Email); err != nil {
		slog.ErrorContext(ctx, "oidc link: upsert identity", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Audit: load connection to get orgID (link callback is a public route, no org context).
	conn, connErr := srv.store.GetSSOConnectionByID(ctx, connID)
	if connErr == nil && conn != nil {
		srv.auditLog(r, audit.Entry{ //nolint:exhaustruct // optional fields
			OrgID:      conn.OrgID,
			ActorID:    &userID,
			Action:     "create",
			EntityType: "sso_identity",
			EntityID:   userID.String(),
			EntityName: claims.Email,
			Success:    true,
			NewState: map[string]any{
				"provider_key":     providerKey,
				"provider_user_id": claims.Sub,
				"email":            claims.Email,
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "linked"})
}
