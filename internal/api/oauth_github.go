// ABOUTME: GitHub OAuth2 login flow: init redirect and callback handler.
// ABOUTME: Matches on GitHub numeric user ID (never email) per PLAN.md §7.2.
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
)

// githubUser is the subset of fields returned by GET https://api.github.com/user.
type githubUser struct {
	ID    int64  `json:"id"`    // immutable numeric ID — the authoritative identity key
	Login string `json:"login"` // display name fallback when Name is empty
	Name  string `json:"name"`
}

// githubEmail is one entry from GET https://api.github.com/user/emails.
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubInitHandler handles GET /api/v1/auth/oauth/github.
// Generates state, sets the oauth_state cookie, and redirects to GitHub's authorize URL.
func (srv *Server) githubInitHandler(w http.ResponseWriter, r *http.Request) {
	if srv.ghOAuth == nil {
		http.Error(w, "GitHub OAuth not configured", http.StatusNotImplemented)
		return
	}
	state, err := generateOAuthState()
	if err != nil {
		slog.ErrorContext(r.Context(), "github oauth init: generate state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	srv.setStateCookie(w, state)
	http.Redirect(w, r, srv.ghOAuth.AuthCodeURL(state), http.StatusFound)
}

// githubCallbackHandler handles GET /api/v1/auth/oauth/github/callback.
// Validates state, exchanges the code, fetches user info, upserts the identity,
// and issues JWT tokens as HttpOnly cookies.
func (srv *Server) githubCallbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Validate CSRF state.
	state := r.URL.Query().Get("state")
	if err := srv.validateStateCookie(r, w, state); err != nil {
		http.Error(w, "invalid state: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 2. Exchange authorization code for access token.
	code := r.URL.Query().Get("code")
	token, err := srv.ghOAuth.Exchange(ctx, code)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: exchange code", "error", err)
		http.Error(w, "authentication failed", http.StatusBadRequest)
		return
	}

	httpClient := srv.ghOAuth.Client(ctx, token)

	// 3. Fetch GitHub user profile.
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.ghAPIBaseURL+"/user", nil)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: build user request", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	resp, err := httpClient.Do(userReq) //nolint:gosec // G704 false positive: ghAPIBaseURL is internal server config
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: fetch user", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	var ghUser githubUser
	if err := json.NewDecoder(resp.Body).Decode(&ghUser); err != nil {
		slog.ErrorContext(ctx, "github oauth: decode user", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	// 4. Fetch verified primary email (user:email scope required).
	emailsReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.ghAPIBaseURL+"/user/emails", nil)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: build emails request", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	resp2, err := httpClient.Do(emailsReq) //nolint:gosec // G704 false positive: ghAPIBaseURL is internal server config
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: fetch emails", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}
	defer resp2.Body.Close() //nolint:errcheck
	var ghEmails []githubEmail
	if err := json.NewDecoder(resp2.Body).Decode(&ghEmails); err != nil {
		slog.ErrorContext(ctx, "github oauth: decode emails", "error", err)
		http.Error(w, "authentication failed", http.StatusInternalServerError)
		return
	}

	var primaryEmail string
	for _, e := range ghEmails {
		if e.Primary && e.Verified {
			primaryEmail = e.Email
			break
		}
	}
	if primaryEmail == "" {
		http.Error(w, "no verified primary email on GitHub account", http.StatusBadRequest)
		return
	}

	// 5. Look up user by GitHub numeric ID — NEVER by email (PLAN.md §7.2).
	providerUserID := strconv.FormatInt(ghUser.ID, 10)
	user, err := srv.store.GetUserByProviderID(ctx, "github", providerUserID)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: get user by provider id", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if user == nil {
		// New user — create account with no password (OAuth-only).
		displayName := ghUser.Name
		if displayName == "" {
			displayName = ghUser.Login
		}
		user, err = srv.store.CreateUser(ctx, primaryEmail, displayName, "", 0)
		if err != nil {
			slog.ErrorContext(ctx, "github oauth: create user", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	// 6. Upsert identity to keep email current (GitHub email may change).
	if err := srv.store.UpsertUserIdentity(ctx, user.ID, "github", providerUserID, primaryEmail); err != nil {
		slog.ErrorContext(ctx, "github oauth: upsert identity", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 7. Issue JWT access + refresh tokens.
	secret := []byte(srv.cfg.JWTSecret)
	jti := uuid.New()
	accessToken, err := auth.IssueAccessToken(secret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: issue access token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshTokenStr, err := auth.IssueRefreshToken(secret, user.ID, int(user.TokenVersion), jti, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "github oauth: issue refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := srv.store.CreateRefreshToken(ctx, jti, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "github oauth: create refresh token", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 8. Set auth cookies and respond.
	for _, cookieStr := range authCookies(accessToken, refreshTokenStr, srv.cfg.CookieSecure) {
		w.Header().Add("Set-Cookie", cookieStr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"user_id": user.ID.String()})
}
