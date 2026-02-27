// ABOUTME: HTTP handlers for authentication: register, login, refresh, logout, me.
// ABOUTME: All auth endpoints live at /api/v1/auth/... and are rate-limited.
package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/auth"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// Token TTLs per PLAN.md §7.1.
const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
	gracePeriod     = 60 * time.Second

	// dummyPasswordHash is a valid PHC-format argon2id hash used for login timing
	// normalization. Running VerifyPassword against this for nonexistent users
	// prevents email enumeration via response time differences.
	dummyPasswordHash = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" //nolint:gosec // G101 false positive: public dummy hash for timing normalization, not a real credential
)

// pgErrCode extracts the Postgres error code from err, or "" if err is not a pg error.
func pgErrCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// authCookies returns Set-Cookie header values for the access and refresh tokens.
// refresh_token is scoped to /api/v1/auth to limit its transmission surface.
func authCookies(accessToken, refreshToken string, secure bool) []string {
	access := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(accessTokenTTL.Seconds()),
	}
	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(refreshTokenTTL.Seconds()),
	}
	return []string{access.String(), refresh.String()}
}

// clearAuthCookies returns Set-Cookie headers that immediately expire both auth cookies.
func clearAuthCookies(secure bool) []string {
	access := &http.Cookie{
		Name:     "access_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	return []string{access.String(), refresh.String()}
}

// ── Register ──────────────────────────────────────────────────────────────────

// registerInput is the request body for POST /auth/register.
type registerInput struct {
	Body struct {
		Email       string `json:"email"        format:"email" maxLength:"254"  doc:"User email address"`
		Password    string `json:"password"     minLength:"8"  maxLength:"1024" doc:"Password (min 8 characters)"`
		DisplayName string `json:"display_name,omitempty"       doc:"Display name (optional)"`
	}
}

// registerOutput is the response body for POST /auth/register.
type registerOutput struct {
	Status int
	Body   struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id,omitempty"`
	}
}

// registerHandler handles POST /api/v1/auth/register.
// In "open" mode the first registered user gets a default org (owner role).
func (srv *Server) registerHandler(ctx context.Context, input *registerInput) (*registerOutput, error) {
	if srv.cfg.RegistrationMode != "open" {
		return nil, huma.Error403Forbidden("registration is not open on this server")
	}

	// Reject duplicate email before the expensive hash.
	existing, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		slog.ErrorContext(ctx, "register: lookup email", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if existing != nil {
		return nil, huma.Error409Conflict("email already registered")
	}

	// Snapshot user count before creation to detect first-user scenario.
	priorCount, err := srv.store.CountUsers(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "register: count users", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	defer srv.releaseArgon2()

	hash, err := auth.HashPassword(input.Body.Password)
	if err != nil {
		slog.ErrorContext(ctx, "register: hash password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	displayName := input.Body.DisplayName
	if displayName == "" {
		// Derive a display name from the email local-part.
		if at := strings.Index(input.Body.Email, "@"); at > 0 {
			displayName = input.Body.Email[:at]
		} else {
			displayName = input.Body.Email
		}
	}

	user, err := srv.store.CreateUser(ctx, input.Body.Email, displayName, hash, 1)
	if err != nil {
		if pgErrCode(err) == "23505" { // unique_violation — race on concurrent register
			return nil, huma.Error409Conflict("email already registered")
		}
		slog.ErrorContext(ctx, "register: create user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &registerOutput{}
	out.Status = http.StatusCreated
	out.Body.UserID = user.ID.String()

	// Bootstrap a default org for the first user in open mode.
	if priorCount == 0 {
		orgName := displayName + "'s Organization"
		org, err := srv.store.CreateOrgWithOwner(ctx, orgName, user.ID)
		if err != nil {
			slog.ErrorContext(ctx, "register: create org", "error", err)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.Body.OrgID = org.ID.String()
	}

	return out, nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

// loginInput is the request body for POST /auth/login.
type loginInput struct {
	Body struct {
		Email    string `json:"email"    format:"email" maxLength:"254"  doc:"User email"`
		Password string `json:"password" minLength:"8"  maxLength:"1024" doc:"Password"`
	}
}

// loginOutput returns auth cookies (no JSON body needed).
type loginOutput struct {
	SetCookie []string `header:"Set-Cookie"`
}

// loginHandler handles POST /api/v1/auth/login.
// Nonexistent users still run argon2 to normalize response timing (prevents email enumeration).
func (srv *Server) loginHandler(ctx context.Context, input *loginInput) (*loginOutput, error) {
	secret := []byte(srv.cfg.JWTSecret)

	user, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		slog.ErrorContext(ctx, "login: lookup email", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Timing normalization: always spend argon2 time regardless of whether the user exists.
	if user == nil || !user.PasswordHash.Valid {
		if !srv.acquireArgon2() {
			return nil, huma.Error503ServiceUnavailable("server busy, please retry")
		}
		_, _ = auth.VerifyPassword(input.Body.Password, dummyPasswordHash)
		srv.releaseArgon2()
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	ok, err := auth.VerifyPassword(input.Body.Password, user.PasswordHash.String)
	srv.releaseArgon2()
	if err != nil {
		slog.ErrorContext(ctx, "login: verify password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !ok {
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	// Issue tokens.
	jti := uuid.New()
	accessToken, err := auth.IssueAccessToken(secret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "login: issue access token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	refreshToken, err := auth.IssueRefreshToken(secret, user.ID, int(user.TokenVersion), jti, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "login: issue refresh token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if err := srv.store.CreateRefreshToken(ctx, jti, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "login: create refresh token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Non-fatal — last_login_at is informational only.
	if err := srv.store.UpdateLastLogin(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "login: update last login", "error", err)
	}

	return &loginOutput{SetCookie: authCookies(accessToken, refreshToken, srv.cfg.CookieSecure)}, nil
}

// ── Refresh ───────────────────────────────────────────────────────────────────

// refreshInput reads the refresh_token cookie.
type refreshInput struct {
	RefreshToken string `cookie:"refresh_token" doc:"Refresh token cookie"`
}

// refreshOutput returns new auth cookies.
type refreshOutput struct {
	SetCookie []string `header:"Set-Cookie"`
}

// refreshHandler handles POST /api/v1/auth/refresh.
// Implements JTI rotation with 60-second grace window and theft detection per PLAN.md §7.1.
func (srv *Server) refreshHandler(ctx context.Context, input *refreshInput) (*refreshOutput, error) {
	if input.RefreshToken == "" {
		return nil, huma.Error401Unauthorized("refresh token required")
	}

	secret := []byte(srv.cfg.JWTSecret)
	claims, err := auth.ParseRefreshToken(input.RefreshToken, secret)
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired refresh token")
	}

	stored, err := srv.store.GetRefreshToken(ctx, claims.JTI)
	if err != nil {
		slog.ErrorContext(ctx, "refresh: get token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if stored == nil {
		return nil, huma.Error401Unauthorized("unknown refresh token")
	}

	if stored.UsedAt.Valid {
		if time.Since(stored.UsedAt.Time) <= gracePeriod {
			// Grace window: concurrent-tab scenario — re-issue based on the replacement.
			return srv.refreshGrace(ctx, stored, secret)
		}
		// Outside grace window: token reuse without grace → treat as theft.
		if _, incrErr := srv.store.IncrementTokenVersion(ctx, stored.UserID); incrErr != nil {
			slog.ErrorContext(ctx, "refresh: increment token version on theft", "error", incrErr)
		}
		return nil, huma.Error401Unauthorized("refresh token already used")
	}

	// Normal path: token not yet used.
	user, err := srv.store.GetUserByID(ctx, stored.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "refresh: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	// Version check detects logout-all and password changes.
	if int(user.TokenVersion) != int(stored.TokenVersion) {
		return nil, huma.Error401Unauthorized("session invalidated")
	}

	return srv.issueRefreshPair(ctx, user, stored.Jti, secret)
}

// refreshGrace handles re-issue within the 60-second grace window.
// The original token (orig) was already used; we advance to its replacement.
func (srv *Server) refreshGrace(ctx context.Context, orig *generated.RefreshToken, secret []byte) (*refreshOutput, error) {
	if !orig.ReplacedByJti.Valid {
		return nil, huma.Error401Unauthorized("refresh token invalid")
	}
	tokenB, err := srv.store.GetRefreshToken(ctx, orig.ReplacedByJti.UUID)
	if err != nil {
		slog.ErrorContext(ctx, "refresh grace: get replacement", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if tokenB == nil || tokenB.UsedAt.Valid {
		return nil, huma.Error401Unauthorized("refresh token invalid")
	}
	user, err := srv.store.GetUserByID(ctx, tokenB.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "refresh grace: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if int(user.TokenVersion) != int(tokenB.TokenVersion) {
		return nil, huma.Error401Unauthorized("session invalidated")
	}
	// Advance the chain: consume token B, issue token C.
	return srv.issueRefreshPair(ctx, user, tokenB.Jti, secret)
}

// issueRefreshPair issues a new access + refresh JWT pair and marks oldJTI as used.
func (srv *Server) issueRefreshPair(ctx context.Context, user *generated.User, oldJTI uuid.UUID, secret []byte) (*refreshOutput, error) {
	newJTI := uuid.New()
	accessToken, err := auth.IssueAccessToken(secret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "refresh: issue access token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	refreshToken, err := auth.IssueRefreshToken(secret, user.ID, int(user.TokenVersion), newJTI, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "refresh: issue refresh token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if err := srv.store.CreateRefreshToken(ctx, newJTI, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "refresh: create new token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if err := srv.store.MarkRefreshTokenUsed(ctx, oldJTI, newJTI); err != nil {
		slog.ErrorContext(ctx, "refresh: mark old token used", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	return &refreshOutput{SetCookie: authCookies(accessToken, refreshToken, srv.cfg.CookieSecure)}, nil
}

// ── Logout ────────────────────────────────────────────────────────────────────

// logoutInput reads the refresh_token cookie for invalidation.
type logoutInput struct {
	RefreshToken string `cookie:"refresh_token" doc:"Refresh token cookie"`
}

// logoutOutput clears auth cookies.
type logoutOutput struct {
	SetCookie []string `header:"Set-Cookie"`
}

// logoutHandler handles POST /api/v1/auth/logout.
// Marks the refresh token as used (no replacement) and clears auth cookies.
func (srv *Server) logoutHandler(ctx context.Context, input *logoutInput) (*logoutOutput, error) {
	if input.RefreshToken != "" {
		claims, err := auth.ParseRefreshToken(input.RefreshToken, []byte(srv.cfg.JWTSecret))
		if err == nil {
			// Mark the token used with itself as the "replacement" to close the chain.
			if err := srv.store.MarkRefreshTokenUsed(ctx, claims.JTI, claims.JTI); err != nil {
				slog.WarnContext(ctx, "logout: mark token used", "error", err)
				// Non-fatal — cookies are cleared regardless.
			}
		}
	}
	return &logoutOutput{SetCookie: clearAuthCookies(srv.cfg.CookieSecure)}, nil
}

// ── Me ────────────────────────────────────────────────────────────────────────

// meInput reads the access_token cookie for authentication.
type meInput struct {
	AccessToken string `cookie:"access_token" doc:"Access token cookie"`
}

// orgEntry is an org membership summary in the /auth/me response.
type orgEntry struct {
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// meOutput is the response body for GET /auth/me.
type meOutput struct {
	Body struct {
		UserID      string     `json:"user_id"`
		Email       string     `json:"email"`
		DisplayName string     `json:"display_name"`
		Orgs        []orgEntry `json:"orgs"`
	}
}

// meHandler handles GET /api/v1/auth/me.
func (srv *Server) meHandler(ctx context.Context, input *meInput) (*meOutput, error) {
	if input.AccessToken == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(input.AccessToken, []byte(srv.cfg.JWTSecret))
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired access token")
	}

	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "me: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	orgRows, err := srv.store.ListUserOrgs(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "me: list orgs", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &meOutput{}
	out.Body.UserID = user.ID.String()
	out.Body.Email = user.Email
	out.Body.DisplayName = user.DisplayName
	out.Body.Orgs = make([]orgEntry, 0, len(orgRows))
	for _, row := range orgRows {
		out.Body.Orgs = append(out.Body.Orgs, orgEntry{
			OrgID: row.OrgID.String(),
			Name:  row.Name,
			Role:  row.Role,
		})
	}
	return out, nil
}

// ── Change password ───────────────────────────────────────────────────────────

// changePasswordInput reads the access token cookie and the password change body.
type changePasswordInput struct {
	AccessToken string `cookie:"access_token" doc:"Access token cookie"`
	Body        struct {
		CurrentPassword string `json:"current_password" minLength:"1"  maxLength:"1024" doc:"Current password"`
		NewPassword     string `json:"new_password"     minLength:"8"  maxLength:"1024" doc:"New password (min 8 characters)"`
	}
}

// changePasswordOutput has no body — 200 on success.
type changePasswordOutput struct{}

// changePasswordHandler handles POST /api/v1/auth/change-password.
// Verifies the current password, hashes the new one, and increments token_version
// to invalidate all active refresh tokens.
func (srv *Server) changePasswordHandler(ctx context.Context, input *changePasswordInput) (*changePasswordOutput, error) {
	if input.AccessToken == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(input.AccessToken, []byte(srv.cfg.JWTSecret))
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired access token")
	}

	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "change-password: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !user.PasswordHash.Valid {
		return nil, huma.Error400BadRequest("account uses OAuth authentication — password change not supported")
	}

	// Verify current password (argon2 semaphore, sequential — not simultaneous).
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	ok, err := auth.VerifyPassword(input.Body.CurrentPassword, user.PasswordHash.String)
	srv.releaseArgon2()
	if err != nil {
		slog.ErrorContext(ctx, "change-password: verify", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !ok {
		return nil, huma.Error401Unauthorized("current password incorrect")
	}

	// Hash the new password.
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	newHash, err := auth.HashPassword(input.Body.NewPassword)
	srv.releaseArgon2()
	if err != nil {
		slog.ErrorContext(ctx, "change-password: hash", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// UpdatePasswordHash also increments token_version, invalidating all refresh tokens.
	if err := srv.store.UpdatePasswordHash(ctx, user.ID, newHash, 1); err != nil {
		slog.ErrorContext(ctx, "change-password: update hash", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	return &changePasswordOutput{}, nil
}

// ── Invitations (public + authenticated) ──────────────────────────────────────

// getInvitationInput reads the token path parameter.
type getInvitationInput struct {
	Token string `path:"token" doc:"Invitation token"`
}

// getInvitationOutput is the response for GET /auth/invitations/{token}.
// Returns org name, role, and expiry. Does NOT expose org_id or email.
type getInvitationOutput struct {
	Body struct {
		OrgName   string `json:"org_name"`
		Role      string `json:"role"`
		ExpiresAt string `json:"expires_at"`
	}
}

// getInvitationHandler handles GET /api/v1/auth/invitations/{token}.
// Public endpoint — no authentication required.
func (srv *Server) getInvitationHandler(ctx context.Context, input *getInvitationInput) (*getInvitationOutput, error) {
	inv, err := srv.store.GetInvitationByToken(ctx, input.Token)
	if err != nil {
		slog.ErrorContext(ctx, "get invitation", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if inv == nil {
		return nil, huma.Error404NotFound("invitation not found")
	}
	if time.Now().After(inv.ExpiresAt) || inv.AcceptedAt.Valid {
		return nil, huma.NewError(http.StatusGone, "invitation has expired or has already been used")
	}

	org, err := srv.store.GetOrgByID(ctx, inv.OrgID)
	if err != nil || org == nil {
		slog.ErrorContext(ctx, "get invitation org", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &getInvitationOutput{}
	out.Body.OrgName = org.Name
	out.Body.Role = inv.Role
	out.Body.ExpiresAt = inv.ExpiresAt.Format(time.RFC3339)
	return out, nil
}

// acceptInvitationInput reads the token path parameter and access_token cookie.
type acceptInvitationInput struct {
	Token       string `path:"token"        doc:"Invitation token"`
	AccessToken string `cookie:"access_token" doc:"Access token cookie"`
}

// acceptInvitationOutput has no body — 200 on success.
type acceptInvitationOutput struct{}

// acceptInvitationHandler handles POST /api/v1/auth/invitations/{token}/accept.
// Requires authentication. Idempotent — if the caller is already a member, returns 200.
func (srv *Server) acceptInvitationHandler(ctx context.Context, input *acceptInvitationInput) (*acceptInvitationOutput, error) {
	if input.AccessToken == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(input.AccessToken, []byte(srv.cfg.JWTSecret))
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired access token")
	}

	inv, err := srv.store.GetInvitationByToken(ctx, input.Token)
	if err != nil {
		slog.ErrorContext(ctx, "accept invitation: get", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if inv == nil {
		return nil, huma.Error404NotFound("invitation not found")
	}
	if time.Now().After(inv.ExpiresAt) {
		return nil, huma.NewError(http.StatusGone, "invitation has expired")
	}

	// Idempotency: if the caller is already a member, return success immediately.
	currentRole, err := srv.store.GetOrgMemberRole(ctx, inv.OrgID, claims.UserID)
	if err != nil {
		slog.ErrorContext(ctx, "accept invitation: check membership", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if currentRole != nil {
		return &acceptInvitationOutput{}, nil
	}

	// Invitation already accepted by someone else.
	if inv.AcceptedAt.Valid {
		return nil, huma.NewError(http.StatusGone, "invitation has already been used")
	}

	if err := srv.store.AcceptOrgInvitation(ctx, inv.OrgID, claims.UserID, inv.Role, inv.ID); err != nil {
		slog.ErrorContext(ctx, "accept invitation: accept", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	return &acceptInvitationOutput{}, nil
}

// ── Route registration ────────────────────────────────────────────────────────

// registerAuthRoutes registers all auth-related routes on the huma API.
func registerAuthRoutes(api huma.API, srv *Server) {
	huma.Register(api, huma.Operation{
		OperationID:   "register",
		Method:        http.MethodPost,
		Path:          "/auth/register",
		Tags:          []string{"auth"},
		Summary:       "Register a new user account",
		DefaultStatus: http.StatusCreated,
	}, srv.registerHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "login",
		Method:        http.MethodPost,
		Path:          "/auth/login",
		Tags:          []string{"auth"},
		Summary:       "Log in and receive auth cookies",
		DefaultStatus: http.StatusOK,
	}, srv.loginHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "refresh-token",
		Method:        http.MethodPost,
		Path:          "/auth/refresh",
		Tags:          []string{"auth"},
		Summary:       "Rotate the refresh token and issue a new access token",
		DefaultStatus: http.StatusOK,
	}, srv.refreshHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodPost,
		Path:          "/auth/logout",
		Tags:          []string{"auth"},
		Summary:       "Log out and clear auth cookies",
		DefaultStatus: http.StatusOK,
	}, srv.logoutHandler)

	huma.Register(api, huma.Operation{
		OperationID: "get-me",
		Method:      http.MethodGet,
		Path:        "/auth/me",
		Tags:        []string{"auth"},
		Summary:     "Get the current user's profile and org memberships",
	}, srv.meHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "change-password",
		Method:        http.MethodPost,
		Path:          "/auth/change-password",
		Tags:          []string{"auth"},
		Summary:       "Change the authenticated user's password",
		DefaultStatus: http.StatusOK,
	}, srv.changePasswordHandler)

	huma.Register(api, huma.Operation{
		OperationID: "get-invitation",
		Method:      http.MethodGet,
		Path:        "/auth/invitations/{token}",
		Tags:        []string{"auth"},
		Summary:     "Get invitation details (public)",
	}, srv.getInvitationHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "accept-invitation",
		Method:        http.MethodPost,
		Path:          "/auth/invitations/{token}/accept",
		Tags:          []string{"auth"},
		Summary:       "Accept an invitation and join the org",
		DefaultStatus: http.StatusOK,
	}, srv.acceptInvitationHandler)
}
