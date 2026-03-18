// ABOUTME: HTTP handlers for authentication: register, login, refresh, logout, me.
// ABOUTME: All auth endpoints live at /api/v1/auth/... and are rate-limited.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/store"
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
		Password    string `json:"password"     minLength:"16" maxLength:"1024" doc:"Password (min 16 characters)"`
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
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}
	if srv.cfg.RegistrationMode != "open" {
		// Allow first user to bootstrap even in invite-only mode.
		// Mutex serializes concurrent bootstrap attempts to prevent TOCTOU races
		// where two requests both see userCount==0 and both proceed.
		srv.bootstrapMu.Lock()
		userCount, err := srv.store.CountUsers(ctx)
		if err != nil {
			srv.bootstrapMu.Unlock()
			slog.ErrorContext(ctx, "register: count users", "error", err)
			return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
		}
		if userCount > 0 {
			srv.bootstrapMu.Unlock()
			return nil, huma.Error403Forbidden("registration is disabled — use an invitation link")
		}
		// Hold mutex through user creation + bootstrap. Released by defer.
		defer srv.bootstrapMu.Unlock()
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

	// Promote first user to site admin (atomic — no-op if one already exists).
	if err := srv.store.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		slog.ErrorContext(ctx, "register: set first site admin", "error", err)
		// Non-fatal — user is created, they just won't be admin.
	}

	out := &registerOutput{}
	out.Status = http.StatusCreated
	out.Body.UserID = user.ID.String()

	// Atomically bootstrap a default org for the first user.
	orgName := displayName + "'s Organization"
	org, err := srv.store.BootstrapFirstUserOrg(ctx, user.ID, orgName)
	if err != nil {
		// Non-fatal: user is created and can log in. Org can be created manually.
		slog.ErrorContext(ctx, "register: bootstrap org", "error", err)
	}
	if org != nil {
		out.Body.OrgID = org.ID.String()
	}

	// Send email verification (non-blocking — failure doesn't prevent registration).
	if err := srv.sendVerificationEmail(ctx, user.ID, input.Body.Email); err != nil {
		slog.WarnContext(ctx, "register: send verification email failed", "email", input.Body.Email, "error", err)
	}

	return out, nil
}

// ── Login ─────────────────────────────────────────────────────────────────────

// loginInput is the request body for POST /auth/login.
type loginInput struct {
	MFADeviceToken string `cookie:"mfa_device_token" doc:"Remember-device token (optional)"`
	Body           struct {
		Email    string `json:"email"    format:"email" maxLength:"254"  doc:"User email"`
		Password string `json:"password" minLength:"16" maxLength:"1024" doc:"Password"`
	}
}

// loginOutput returns auth cookies and MFA pending state.
type loginOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		UserID  uuid.UUID `json:"user_id"           doc:"Authenticated user ID"`
		Pending []string  `json:"pending"            doc:"Remaining auth steps (empty = fully authenticated)"`
		Methods []string  `json:"methods,omitempty"   doc:"Available MFA methods (only when pending contains mfa_challenge)"`
	}
}

// sha256Hex returns the hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// pendingTokenCookies creates the mfa_pending_token Set-Cookie header.
func pendingTokenCookies(token string, secure bool, ttl time.Duration) []string {
	c := &http.Cookie{
		Name:     "mfa_pending_token",
		Value:    token,
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
	return []string{c.String()}
}

// clearPendingTokenCookie expires the mfa_pending_token cookie.
func clearPendingTokenCookie(secure bool) string {
	c := &http.Cookie{
		Name:     "mfa_pending_token",
		Value:    "",
		Path:     "/api/v1/auth",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	return c.String()
}

// loginHandler handles POST /api/v1/auth/login.
// Nonexistent users still run argon2 to normalize response timing (prevents email enumeration).
func (srv *Server) loginHandler(ctx context.Context, input *loginInput) (*loginOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}
	secret := srv.jwtSecret()

	user, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		slog.ErrorContext(ctx, "login: lookup email", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Reject disabled users with the same response as nonexistent users
	// to prevent account status enumeration.
	if user != nil && user.DisabledAt.Valid {
		if !srv.acquireArgon2() {
			return nil, huma.Error503ServiceUnavailable("server busy, please retry")
		}
		func() {
			defer srv.releaseArgon2()
			_, _ = auth.VerifyPassword(input.Body.Password, dummyPasswordHash)
		}()
		srv.lockout.RecordFailure(ctx, input.Body.Email)
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:       secure.EventAuthLoginFailed,
				Severity:   secure.SeverityWarning,
				ActorIP:    clientIP(ctx),
				ActorEmail: input.Body.Email,
				UserID:     &user.ID,
				Details:    map[string]any{"reason": "account disabled"},
			})
		}
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	// Account lockout check — before argon2 to save CPU on locked accounts.
	// Still normalize timing for locked accounts to prevent lockout status enumeration.
	allowed, retryAfter := srv.lockout.Check(ctx, input.Body.Email)
	if !allowed {
		time.Sleep(50 * time.Millisecond) // timing normalization
		if srv.eventWriter != nil {
			var uid *uuid.UUID
			if user != nil {
				uid = &user.ID
			}
			srv.eventWriter.Write(ctx, secure.Event{
				Type:       secure.EventAuthLoginFailed,
				Severity:   secure.SeverityWarning,
				ActorIP:    clientIP(ctx),
				ActorEmail: input.Body.Email,
				UserID:     uid,
				Details:    map[string]any{"reason": "account locked"},
			})
		}
		retrySeconds := int(retryAfter.Seconds())
		if retrySeconds < 1 {
			retrySeconds = 1
		}
		return nil, huma.Error429TooManyRequests(
			"account temporarily locked due to too many failed login attempts",
			&huma.ErrorDetail{
				Message:  "retry_after_seconds",
				Location: "header",
				Value:    retrySeconds,
			},
		)
	}

	// Timing normalization: always spend argon2 time regardless of whether the user exists.
	if user == nil || !user.PasswordHash.Valid {
		if !srv.acquireArgon2() {
			return nil, huma.Error503ServiceUnavailable("server busy, please retry")
		}
		func() {
			defer srv.releaseArgon2()
			_, _ = auth.VerifyPassword(input.Body.Password, dummyPasswordHash)
		}()
		srv.lockout.RecordFailure(ctx, input.Body.Email)
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:       secure.EventAuthLoginFailed,
				Severity:   secure.SeverityWarning,
				ActorIP:    clientIP(ctx),
				ActorEmail: input.Body.Email,
				Details:    map[string]any{"reason": "invalid credentials"},
			})
		}
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	var ok bool
	func() {
		defer srv.releaseArgon2()
		ok, err = auth.VerifyPassword(input.Body.Password, user.PasswordHash.String)
	}()
	if err != nil {
		slog.ErrorContext(ctx, "login: verify password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !ok {
		srv.lockout.RecordFailure(ctx, input.Body.Email)
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:       secure.EventAuthLoginFailed,
				Severity:   secure.SeverityWarning,
				ActorIP:    clientIP(ctx),
				ActorEmail: input.Body.Email,
				UserID:     &user.ID,
				Details:    map[string]any{"reason": "invalid credentials"},
			})
		}
		// Check if this failure triggered account lockout.
		if locked, _ := srv.lockout.Check(ctx, input.Body.Email); !locked {
			if srv.eventWriter != nil {
				srv.eventWriter.Write(ctx, secure.Event{
					Type:       secure.EventAuthAccountLocked,
					Severity:   secure.SeverityCritical,
					ActorIP:    clientIP(ctx),
					ActorEmail: input.Body.Email,
					UserID:     &user.ID,
				})
			}
		}
		return nil, huma.Error401Unauthorized("invalid credentials")
	}

	// Successful login — reset lockout counter.
	srv.lockout.RecordSuccess(ctx, input.Body.Email)

	// ── MFA / restricted session checks ──────────────────────────────
	var pending []string
	var methods []string

	hasMFA, err := srv.store.UserHasMFACredentials(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "login: check MFA credentials", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if hasMFA {
		// Check remember-device cookie before requiring MFA challenge.
		skipMFA := false
		if input.MFADeviceToken != "" {
			tokenHash := sha256Hex(input.MFADeviceToken)
			valid, valErr := srv.store.ValidateRememberDeviceToken(ctx, user.ID, tokenHash)
			if valErr != nil {
				slog.WarnContext(ctx, "login: check device token", "error", valErr)
			}
			if valid {
				skipMFA = true
				if srv.eventWriter != nil {
					srv.eventWriter.Write(ctx, secure.Event{
						Type:     secure.EventMFARememberDeviceUsed,
						Severity: secure.SeverityInfo,
						ActorIP:  clientIP(ctx),
						UserID:   &user.ID,
					})
				}
			}
		}
		if !skipMFA {
			pending = append(pending, "mfa_challenge")
			creds, credErr := srv.store.GetMFACredentialsByUserID(ctx, user.ID)
			if credErr != nil {
				slog.ErrorContext(ctx, "login: get MFA methods", "error", credErr)
				return nil, huma.Error500InternalServerError("internal error")
			}
			for _, c := range creds {
				methods = append(methods, c.Method)
			}
		}
	}

	if user.ForcePasswordReset {
		pending = append(pending, "password_reset")
	}

	if !hasMFA {
		isSiteAdmin, saErr := srv.store.IsSiteAdmin(ctx, user.ID)
		if saErr != nil {
			slog.ErrorContext(ctx, "login: check site admin", "error", saErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		mfaCfg := store.MFAConfig{
			RequiredSiteAdmins: srv.cfg.MFARequiredSiteAdmins,
			RequiredOrgOwners:  srv.cfg.MFARequiredOrgOwners,
		}
		required, mfaErr := srv.store.UserMFARequired(ctx, user.ID, isSiteAdmin, mfaCfg)
		if mfaErr != nil {
			slog.ErrorContext(ctx, "login: check MFA mandate", "error", mfaErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		if required {
			pending = append(pending, "mfa_enrollment_required")
		}
	}

	// Non-fatal — last_login_at is informational only.
	if err := srv.store.UpdateLastLogin(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "login: update last login", "error", err)
	}

	if len(pending) > 0 {
		// Issue restricted pending token instead of full auth tokens.
		pendingToken, ptErr := auth.IssuePendingToken(
			secret, user.ID, int(user.TokenVersion),
			pending, methods, srv.cfg.MFAPendingTokenTTL,
		)
		if ptErr != nil {
			slog.ErrorContext(ctx, "login: issue pending token", "error", ptErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:       secure.EventAuthLoginSuccess,
				Severity:   secure.SeverityInfo,
				ActorIP:    clientIP(ctx),
				ActorEmail: input.Body.Email,
				UserID:     &user.ID,
				Details:    map[string]any{"pending": pending},
			})
		}
		out := &loginOutput{}
		out.Body.UserID = user.ID
		out.Body.Pending = pending
		out.Body.Methods = methods
		out.SetCookie = pendingTokenCookies(pendingToken, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL)
		return out, nil
	}

	// No pending items — issue full access + refresh tokens.
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

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:       secure.EventAuthLoginSuccess,
			Severity:   secure.SeverityInfo,
			ActorIP:    clientIP(ctx),
			ActorEmail: input.Body.Email,
			UserID:     &user.ID,
		})
	}

	out := &loginOutput{}
	out.Body.UserID = user.ID
	out.Body.Pending = []string{}
	out.SetCookie = authCookies(accessToken, refreshToken, srv.cfg.CookieSecure)
	return out, nil
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
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}
	if input.RefreshToken == "" {
		return nil, huma.Error401Unauthorized("refresh token required")
	}

	secret := srv.jwtSecret()
	claims, err := auth.ParseRefreshToken(input.RefreshToken, secret, srv.jwtPreviousSecretBytes())
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
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventAuthTokenReuseDetected,
				Severity: secure.SeverityCritical,
				ActorIP:  clientIP(ctx),
				UserID:   &stored.UserID,
			})
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
		claims, err := auth.ParseRefreshToken(input.RefreshToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
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
		UserID             string     `json:"user_id"`
		Email              string     `json:"email"`
		DisplayName        string     `json:"display_name"`
		IsSiteAdmin        bool       `json:"is_site_admin"`
		ForcePasswordReset bool       `json:"force_password_reset"`
		Orgs               []orgEntry `json:"orgs"`
	}
}

// meHandler handles GET /api/v1/auth/me.
func (srv *Server) meHandler(ctx context.Context, input *meInput) (*meOutput, error) {
	if input.AccessToken == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(input.AccessToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
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

	isSiteAdmin, err := srv.store.IsSiteAdmin(ctx, user.ID)
	if err != nil {
		slog.ErrorContext(ctx, "me: check site admin", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &meOutput{}
	out.Body.UserID = user.ID.String()
	out.Body.Email = user.Email
	out.Body.DisplayName = user.DisplayName
	out.Body.IsSiteAdmin = isSiteAdmin
	out.Body.ForcePasswordReset = user.ForcePasswordReset
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

// changePasswordInput reads the access token or pending token cookie and the
// password change body. In restricted session mode (force_password_reset via
// pending token), current_password is optional.
type changePasswordInput struct {
	AccessToken     string `cookie:"access_token"       doc:"Access token cookie"`
	MFAPendingToken string `cookie:"mfa_pending_token"   doc:"Pending token cookie (restricted session)"`
	Body            struct {
		CurrentPassword *string `json:"current_password,omitempty" maxLength:"1024" doc:"Current password (required in normal mode, optional in restricted mode)"`
		NewPassword     string  `json:"new_password"               minLength:"16" maxLength:"1024" doc:"New password (min 16 characters)"`
	}
}

// changePasswordOutput returns tokens when completing a restricted session.
type changePasswordOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		Pending []string `json:"pending,omitempty" doc:"Remaining pending items (if any)"`
	}
}

// changePasswordHandler handles POST /api/v1/auth/change-password.
// Supports two modes:
//   - Normal: access_token + current_password → verify old password, set new one.
//   - Restricted: mfa_pending_token with "password_reset" → skip current_password
//     (password may be compromised). Issues full tokens or reissues pending token.
func (srv *Server) changePasswordHandler(ctx context.Context, input *changePasswordInput) (*changePasswordOutput, error) {
	var (
		userID        uuid.UUID
		pendingClaims *auth.PendingClaims
		isRestricted  bool
	)

	// Resolve auth context: access token or pending token with "password_reset".
	if input.AccessToken != "" {
		claims, err := auth.ParseAccessToken(input.AccessToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
		if err == nil {
			userID = claims.UserID
		}
	}
	if userID == uuid.Nil && input.MFAPendingToken != "" {
		claims, err := auth.ParsePendingToken(input.MFAPendingToken, srv.jwtSecret())
		if err == nil {
			for _, p := range claims.Pending {
				if p == "password_reset" {
					userID = claims.UserID
					pendingClaims = claims
					isRestricted = true
					break
				}
			}
		}
	}
	if userID == uuid.Nil {
		return nil, huma.Error401Unauthorized("authentication required")
	}

	user, err := srv.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "change-password: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !user.PasswordHash.Valid {
		return nil, huma.Error400BadRequest("account uses OAuth authentication — password change not supported")
	}

	// In normal mode, verify current password. In restricted mode, skip — the
	// password may be compromised (admin forced reset).
	if !isRestricted {
		if input.Body.CurrentPassword == nil || *input.Body.CurrentPassword == "" {
			return nil, huma.Error422UnprocessableEntity("current_password is required")
		}
		if !srv.acquireArgon2() {
			return nil, huma.Error503ServiceUnavailable("server busy, please retry")
		}
		var ok bool
		func() {
			defer srv.releaseArgon2()
			ok, err = auth.VerifyPassword(*input.Body.CurrentPassword, user.PasswordHash.String)
		}()
		if err != nil {
			slog.ErrorContext(ctx, "change-password: verify", "error", err)
			return nil, huma.Error500InternalServerError("internal error")
		}
		if !ok {
			return nil, huma.Error401Unauthorized("current password incorrect")
		}
	}

	// Hash the new password.
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	var newHash string
	func() {
		defer srv.releaseArgon2()
		newHash, err = auth.HashPassword(input.Body.NewPassword)
	}()
	if err != nil {
		slog.ErrorContext(ctx, "change-password: hash", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// UpdatePasswordHash also increments token_version, invalidating all refresh tokens.
	if err := srv.store.UpdatePasswordHash(ctx, user.ID, newHash, 1); err != nil {
		slog.ErrorContext(ctx, "change-password: update hash", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Clear force_password_reset if it was set.
	if err := srv.store.ClearForcePasswordReset(ctx, user.ID); err != nil {
		slog.ErrorContext(ctx, "change-password: clear force reset", "error", err)
		// Non-fatal — password is already changed.
	}

	// Delete remember-device tokens (password change invalidates them).
	if err := srv.store.DeleteRememberDeviceTokens(ctx, user.ID); err != nil {
		slog.WarnContext(ctx, "change-password: delete device tokens", "error", err)
	}

	if srv.eventWriter != nil {
		method := "change_password"
		if isRestricted {
			method = "forced_reset"
		}
		srv.eventWriter.Write(ctx, secure.Event{
			Type:       secure.EventAuthPasswordChanged,
			Severity:   secure.SeverityInfo,
			ActorIP:    clientIP(ctx),
			ActorEmail: user.Email,
			UserID:     &user.ID,
			Details:    map[string]any{"method": method},
		})
		if isRestricted {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventAuthPasswordResetForcedCompleted,
				Severity: secure.SeverityInfo,
				ActorIP:  clientIP(ctx),
				UserID:   &user.ID,
			})
		}
	}

	out := &changePasswordOutput{}

	// In restricted session, progress the pending token.
	if isRestricted && pendingClaims != nil {
		remaining := removePendingItem(pendingClaims.Pending, "password_reset")
		if len(remaining) > 0 {
			// Re-read user to get the incremented token_version.
			freshUser, ruErr := srv.store.GetUserByID(ctx, userID)
			if ruErr != nil || freshUser == nil {
				slog.ErrorContext(ctx, "change-password: re-read user for tv", "error", ruErr)
				return nil, huma.Error500InternalServerError("internal error")
			}
			token, ptErr := auth.IssuePendingToken(
				srv.jwtSecret(), userID, int(freshUser.TokenVersion),
				remaining, nil, srv.cfg.MFAPendingTokenTTL,
			)
			if ptErr != nil {
				slog.ErrorContext(ctx, "change-password: reissue pending token", "error", ptErr)
				return nil, huma.Error500InternalServerError("internal error")
			}
			out.Body.Pending = remaining
			out.SetCookie = pendingTokenCookies(token, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL)
			return out, nil
		}

		// All pending items cleared — re-read user (token_version was incremented).
		user, err = srv.store.GetUserByID(ctx, userID)
		if err != nil || user == nil {
			slog.ErrorContext(ctx, "change-password: re-read user", "error", err)
			return nil, huma.Error500InternalServerError("internal error")
		}
		cookies, tokErr := srv.issueFullAuthTokens(ctx, user)
		if tokErr != nil {
			return nil, tokErr
		}
		out.SetCookie = cookies
		out.SetCookie = append(out.SetCookie, clearPendingTokenCookie(srv.cfg.CookieSecure))
	}

	return out, nil
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
	claims, err := auth.ParseAccessToken(input.AccessToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
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

	// Verify the accepting user's email matches the invitation's target email.
	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "accept invitation: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !strings.EqualFold(user.Email, inv.Email) {
		return nil, huma.Error403Forbidden("invitation was sent to a different email address")
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

	// Auto-verify email — the invitation proves the user controls this email address.
	if !user.EmailVerified {
		if err := srv.store.SetEmailVerified(ctx, claims.UserID); err != nil {
			slog.ErrorContext(ctx, "accept invitation: set email verified", "error", err)
			// Non-fatal — membership is already created.
		}
	}

	if srv.auditWriter != nil {
		srv.auditWriter.Log(ctx, audit.Entry{
			OrgID:      inv.OrgID,
			ActorID:    &claims.UserID,
			ActorEmail: user.Email,
			Action:     "create",
			EntityType: "member",
			EntityID:   claims.UserID.String(),
			EntityName: user.DisplayName,
			Success:    true,
			NewState:   map[string]any{"role": inv.Role},
		})
	}

	return &acceptInvitationOutput{}, nil
}

// ── Auth providers ────────────────────────────────────────────────────────────

// authProvidersOutput is the response body for GET /auth/providers.
type authProvidersOutput struct {
	Body struct {
		GitHub           bool   `json:"github"`
		Google           bool   `json:"google"`
		RegistrationMode string `json:"registration_mode"`
	}
}

// authProvidersHandler handles GET /api/v1/auth/providers.
// Returns which OAuth providers are configured so the frontend can
// conditionally render login buttons.
func (srv *Server) authProvidersHandler(_ context.Context, _ *struct{}) (*authProvidersOutput, error) {
	out := &authProvidersOutput{}
	out.Body.GitHub = srv.ghOAuth != nil
	out.Body.Google = srv.googleOIDC != nil
	out.Body.RegistrationMode = srv.cfg.RegistrationMode
	return out, nil
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

	huma.Register(api, huma.Operation{
		OperationID: "get-auth-providers",
		Method:      http.MethodGet,
		Path:        "/auth/providers",
		Tags:        []string{"auth"},
		Summary:     "List configured auth providers and registration mode",
	}, srv.authProvidersHandler)

	// Password reset — public, no auth required.
	huma.Register(api, huma.Operation{
		OperationID:   "forgot-password",
		Method:        http.MethodPost,
		Path:          "/auth/forgot-password",
		Tags:          []string{"auth"},
		Summary:       "Request a password reset email",
		DefaultStatus: http.StatusOK,
	}, srv.forgotPasswordHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "reset-password",
		Method:        http.MethodPost,
		Path:          "/auth/reset-password",
		Tags:          []string{"auth"},
		Summary:       "Reset password using a reset token",
		DefaultStatus: http.StatusOK,
	}, srv.resetPasswordHandler)

	// Email verification — verify-email is public, resend-verification requires auth.
	huma.Register(api, huma.Operation{
		OperationID:   "verify-email",
		Method:        http.MethodPost,
		Path:          "/auth/verify-email",
		Tags:          []string{"auth"},
		Summary:       "Verify email address using a verification token",
		DefaultStatus: http.StatusOK,
	}, srv.verifyEmailHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "resend-verification",
		Method:        http.MethodPost,
		Path:          "/auth/resend-verification",
		Tags:          []string{"auth"},
		Summary:       "Resend email verification (requires authentication)",
		DefaultStatus: http.StatusOK,
	}, srv.resendVerificationHandler)
}
