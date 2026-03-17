// ABOUTME: HTTP handlers for MFA challenge, verify, enrollment, and management.
// ABOUTME: All MFA endpoints live at /api/v1/auth/mfa/... and consume pending token cookies.
package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/notify"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// ── MFA Challenge ────────────────────────────────────────────────────────────

type mfaChallengeInput struct {
	MFAPendingToken string `cookie:"mfa_pending_token"`
	Body            struct {
		Method string `json:"method" enum:"totp,email_otp" doc:"MFA method to challenge"`
	}
}

type mfaChallengeOutput struct {
	SetCookie []string `header:"Set-Cookie"`
}

// mfaChallengeHandler handles POST /api/v1/auth/mfa/challenge.
// For email_otp: generates and sends a 6-digit code.
// For totp: acknowledges readiness (no server action needed).
func (srv *Server) mfaChallengeHandler(ctx context.Context, input *mfaChallengeInput) (*mfaChallengeOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	claims, err := srv.validatePendingToken(input.MFAPendingToken, "mfa_challenge")
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired pending token")
	}

	if input.Body.Method == "totp" {
		// TOTP is client-side — just reissue the pending token with fresh TTL.
		out := &mfaChallengeOutput{}
		out.SetCookie = srv.reissuePendingTokenCookies(claims)
		return out, nil
	}

	// Email OTP: generate code, store hash, send email.
	// Rate-limit: max N codes per hour per user.
	since := time.Now().Add(-1 * time.Hour)
	count, countErr := srv.store.CountRecentEmailOTPChallenges(ctx, claims.UserID, since)
	if countErr != nil {
		slog.ErrorContext(ctx, "mfa-challenge: count recent OTPs", "error", countErr)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if count >= int64(srv.cfg.MFAEmailOTPMaxPerHour) {
		return nil, huma.Error429TooManyRequests("too many email OTP requests — try again later")
	}

	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "mfa-challenge: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	code, err := generateEmailOTPCode()
	if err != nil {
		slog.ErrorContext(ctx, "mfa-challenge: generate code", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	codeHash := sha256Hex(code)
	expiresAt := time.Now().Add(srv.cfg.MFAEmailOTPTTL)
	if err := srv.store.CreateEmailOTPChallenge(ctx, claims.UserID, codeHash, expiresAt); err != nil {
		slog.ErrorContext(ctx, "mfa-challenge: create challenge", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Send email (non-blocking if SMTP not configured — code is still in DB for testing).
	if err := srv.sendMFAOTPEmail(ctx, user.Email, code); err != nil {
		slog.WarnContext(ctx, "mfa-challenge: send email", "error", err)
		// Don't fail the request — the code is in the DB.
	}

	out := &mfaChallengeOutput{}
	out.SetCookie = srv.reissuePendingTokenCookies(claims)
	return out, nil
}

// ── MFA Verify ───────────────────────────────────────────────────────────────

type mfaVerifyInput struct {
	MFAPendingToken string `cookie:"mfa_pending_token"`
	Body            struct {
		Method         string `json:"method"          enum:"totp,email_otp,recovery" doc:"MFA method"`
		Code           string `json:"code"            minLength:"1" maxLength:"20"    doc:"Verification code"`
		RememberDevice *bool  `json:"remember_device,omitempty" doc:"Issue remember-device token"`
	}
}

type mfaVerifyOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		UserID  uuid.UUID `json:"user_id"`
		Pending []string  `json:"pending"`
		Methods []string  `json:"methods,omitempty"`
	}
}

// mfaVerifyHandler handles POST /api/v1/auth/mfa/verify.
// Validates the submitted code against the enrolled MFA method, then either
// progresses the pending token or issues full auth tokens.
func (srv *Server) mfaVerifyHandler(ctx context.Context, input *mfaVerifyInput) (*mfaVerifyOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	claims, err := srv.validatePendingToken(input.MFAPendingToken, "mfa_challenge")
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired pending token")
	}

	// Verify token_version matches DB (prevents stale tokens after admin actions).
	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, huma.Error401Unauthorized("invalid session")
	}
	if int(user.TokenVersion) != claims.TokenVersion {
		return nil, huma.Error401Unauthorized("session invalidated — please log in again")
	}

	// Verify the code based on method.
	var verified bool
	switch input.Body.Method {
	case "totp":
		verified, err = srv.verifyTOTP(ctx, claims.UserID, input.Body.Code)
	case "email_otp":
		verified, err = srv.verifyEmailOTP(ctx, claims.UserID, input.Body.Code)
	case "recovery":
		var remaining int
		verified, remaining, err = srv.store.VerifyRecoveryCode(ctx, claims.UserID, input.Body.Code)
		if verified {
			slog.InfoContext(ctx, "mfa-verify: recovery code used", "user_id", claims.UserID, "remaining", remaining)
		}
	default:
		return nil, huma.Error400BadRequest("unsupported MFA method")
	}

	if err != nil {
		slog.ErrorContext(ctx, "mfa-verify: verification error", "method", input.Body.Method, "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !verified {
		srv.lockout.RecordFailure(ctx, user.Email)
		return nil, huma.Error401Unauthorized("invalid verification code")
	}

	// MFA verified — progress the pending token.
	remaining := removePendingItem(claims.Pending, "mfa_challenge")

	out := &mfaVerifyOutput{}
	out.Body.UserID = claims.UserID

	if len(remaining) > 0 {
		// More steps needed — reissue pending token with remaining items.
		secret := []byte(srv.cfg.JWTSecret)
		// Methods are no longer relevant after MFA challenge is cleared.
		pendingToken, ptErr := auth.IssuePendingToken(
			secret, claims.UserID, claims.TokenVersion,
			remaining, nil, srv.cfg.MFAPendingTokenTTL,
		)
		if ptErr != nil {
			slog.ErrorContext(ctx, "mfa-verify: reissue pending token", "error", ptErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.Body.Pending = remaining
		out.SetCookie = pendingTokenCookies(pendingToken, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL)
		return out, nil
	}

	// All steps complete — issue full auth tokens.
	out.Body.Pending = []string{}
	cookies, err := srv.issueFullAuthTokens(ctx, user)
	if err != nil {
		return nil, err
	}
	out.SetCookie = cookies
	// Clear the pending token cookie.
	out.SetCookie = append(out.SetCookie, clearPendingTokenCookie(srv.cfg.CookieSecure))

	// Handle remember-device if requested.
	if input.Body.RememberDevice != nil && *input.Body.RememberDevice {
		deviceCookie, rdErr := srv.issueRememberDeviceToken(ctx, claims.UserID)
		if rdErr != nil {
			slog.WarnContext(ctx, "mfa-verify: issue device token", "error", rdErr)
		} else if deviceCookie != "" {
			out.SetCookie = append(out.SetCookie, deviceCookie)
		}
	}

	return out, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// validatePendingToken parses the pending token and checks that the expected
// step is the first item in the pending array.
func (srv *Server) validatePendingToken(tokenStr string, expectedStep string) (*auth.PendingClaims, error) {
	if tokenStr == "" {
		return nil, fmt.Errorf("missing pending token")
	}
	claims, err := auth.ParsePendingToken(tokenStr, []byte(srv.cfg.JWTSecret))
	if err != nil {
		return nil, err
	}
	if len(claims.Pending) == 0 || claims.Pending[0] != expectedStep {
		return nil, fmt.Errorf("unexpected pending step: want %s, got %v", expectedStep, claims.Pending)
	}
	return claims, nil
}

// reissuePendingTokenCookies reissues the pending token with a fresh TTL.
func (srv *Server) reissuePendingTokenCookies(claims *auth.PendingClaims) []string {
	secret := []byte(srv.cfg.JWTSecret)
	token, err := auth.IssuePendingToken(
		secret, claims.UserID, claims.TokenVersion,
		claims.Pending, claims.Methods, srv.cfg.MFAPendingTokenTTL,
	)
	if err != nil {
		slog.Error("mfa: reissue pending token", "error", err)
		return nil
	}
	return pendingTokenCookies(token, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL)
}

// issueFullAuthTokens creates and returns access + refresh token cookies.
func (srv *Server) issueFullAuthTokens(ctx context.Context, user *generated.User) ([]string, error) {
	secret := []byte(srv.cfg.JWTSecret)
	jti := uuid.New()
	accessToken, err := auth.IssueAccessToken(secret, user.ID, int(user.TokenVersion), accessTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "mfa: issue access token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	refreshToken, err := auth.IssueRefreshToken(secret, user.ID, int(user.TokenVersion), jti, refreshTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "mfa: issue refresh token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if err := srv.store.CreateRefreshToken(ctx, jti, user.ID, int(user.TokenVersion), time.Now().Add(refreshTokenTTL)); err != nil {
		slog.ErrorContext(ctx, "mfa: create refresh token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	return authCookies(accessToken, refreshToken, srv.cfg.CookieSecure), nil
}

// verifyTOTP validates a TOTP code against the user's enrolled credential.
func (srv *Server) verifyTOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	cred, err := srv.store.GetMFACredentialByUserAndMethod(ctx, userID, "totp")
	if err != nil {
		return false, fmt.Errorf("get TOTP credential: %w", err)
	}
	if cred == nil {
		return false, nil
	}

	// Decrypt the TOTP secret.
	encKey, err := srv.ssoEncryptionKey()
	if err != nil {
		return false, fmt.Errorf("encryption key: %w", err)
	}
	prevKey := srv.ssoEncryptionKeyPrevious()
	secretBytes, err := crypto.DecryptWithFallback(encKey, prevKey, cred.SecretEnc)
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	// Validate the TOTP code.
	valid, err := totp.ValidateCustom(code, string(secretBytes), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:     1,
		Digits:   6,
		Algorithm: 0, // SHA1
	})
	if err != nil {
		return false, fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return false, nil
	}

	// Replay prevention: check last_used_step.
	currentStep := time.Now().Unix() / 30
	if cred.LastUsedStep.Valid && cred.LastUsedStep.Int64 >= currentStep {
		return false, nil // replay
	}

	// Update last_used_step.
	if err := srv.store.UpdateMFACredentialLastUsed(ctx, cred.ID, sql.NullInt64{Int64: currentStep, Valid: true}); err != nil {
		slog.WarnContext(ctx, "mfa: update TOTP last_used_step", "error", err)
	}

	return true, nil
}

// verifyEmailOTP validates an email OTP code against the active challenge.
func (srv *Server) verifyEmailOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	codeHash := sha256Hex(code)
	return srv.store.VerifyEmailOTPChallenge(ctx, userID, codeHash, int32(srv.cfg.MFAChallengeMaxAttempts))
}

// generateEmailOTPCode generates a cryptographically random 6-digit code.
func generateEmailOTPCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// generateSecureToken returns n random bytes as a hex string.
func generateSecureToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sendMFAOTPEmail sends a verification code email to the user.
func (srv *Server) sendMFAOTPEmail(ctx context.Context, email, code string) error {
	if srv.cfg.SMTPHost == "" {
		slog.WarnContext(ctx, "mfa-otp: SMTP not configured, skipping email", "email", email)
		return nil
	}

	subject, htmlBody, textBody, err := notify.RenderMFAOTP(notify.MFAOTPData{
		Code:      code,
		ExpiresIn: formatTTL(srv.cfg.MFAEmailOTPTTL),
	})
	if err != nil {
		return fmt.Errorf("render MFA OTP email: %w", err)
	}

	smtpCfg := notify.SmtpConfig{
		Host:     srv.cfg.SMTPHost,
		Port:     srv.cfg.SMTPPort,
		From:     srv.cfg.SMTPFrom,
		Username: srv.cfg.SMTPUsername,
		Password: srv.cfg.SMTPPassword,
		TLS:      srv.cfg.SMTPTLS,
	}
	return notify.EmailSend(ctx, smtpCfg, []string{email}, subject, htmlBody, textBody)
}

// removePendingItem returns a new slice without the specified item.
func removePendingItem(pending []string, item string) []string {
	result := make([]string, 0, len(pending))
	for _, p := range pending {
		if p != item {
			result = append(result, p)
		}
	}
	return result
}

// issueRememberDeviceToken creates a device token if the user's orgs allow it.
// Returns the Set-Cookie value, or "" if not allowed.
func (srv *Server) issueRememberDeviceToken(ctx context.Context, userID uuid.UUID) (string, error) {
	allowed, err := srv.store.AllUserOrgsAllowRememberDevice(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("check remember-device: %w", err)
	}
	if !allowed {
		return "", nil
	}

	days, err := srv.store.MinRememberDeviceDays(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("get remember-device days: %w", err)
	}

	token, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("generate device token: %w", err)
	}
	tokenHash := sha256Hex(token)
	expiresAt := time.Now().AddDate(0, 0, int(days))
	if err := srv.store.CreateRememberDeviceToken(ctx, userID, tokenHash, expiresAt); err != nil {
		return "", fmt.Errorf("store device token: %w", err)
	}

	cookie := &http.Cookie{
		Name:     "mfa_device_token",
		Value:    token,
		Path:     "/api/v1/auth/login",
		HttpOnly: true,
		Secure:   srv.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(days) * 86400,
	}
	return cookie.String(), nil
}

// ── Route registration ────────────────────────────────────────────────────────

// registerMFARoutes registers MFA challenge and verify routes on the huma API.
func registerMFARoutes(api huma.API, srv *Server) {
	huma.Register(api, huma.Operation{
		OperationID:   "mfa-challenge",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/challenge",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Request MFA challenge (email OTP code or signal TOTP readiness)",
		DefaultStatus: http.StatusOK,
	}, srv.mfaChallengeHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "mfa-verify",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/verify",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Submit MFA verification code",
		DefaultStatus: http.StatusOK,
	}, srv.mfaVerifyHandler)
}
