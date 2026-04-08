// ABOUTME: HTTP handlers for MFA challenge, verify, enrollment, and management.
// ABOUTME: All MFA endpoints live at /api/v1/auth/mfa/... and consume pending token cookies.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// enrollmentTokenTTL is the duration a TOTP enrollment token is valid.
const enrollmentTokenTTL = 5 * time.Minute

// totpValidateOpts are the TOTP validation parameters used for both
// login verification and enrollment confirmation.
var totpValidateOpts = totp.ValidateOpts{
	Period:    30,
	Skew:      1,
	Digits:    6,
	Algorithm: otp.AlgorithmSHA1,
}

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
		cookies, reissueErr := srv.reissuePendingTokenCookies(claims)
		if reissueErr != nil {
			slog.ErrorContext(ctx, "mfa-challenge: reissue pending token", "error", reissueErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out := &mfaChallengeOutput{}
		out.SetCookie = cookies
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
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAEmailOTPRateLimited,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &claims.UserID,
			})
		}
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

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAChallengeRequested,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &claims.UserID,
			Details:  map[string]any{"method": "email_otp"},
		})
	}

	cookies, reissueErr := srv.reissuePendingTokenCookies(claims)
	if reissueErr != nil {
		slog.ErrorContext(ctx, "mfa-challenge: reissue pending token", "error", reissueErr)
		return nil, huma.Error500InternalServerError("internal error")
	}
	out := &mfaChallengeOutput{}
	out.SetCookie = cookies
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
			if srv.eventWriter != nil {
				srv.eventWriter.Write(ctx, secure.Event{
					Type:     secure.EventMFARecoveryCodeUsed,
					Severity: secure.SeverityWarning,
					ActorIP:  clientIP(ctx),
					UserID:   &claims.UserID,
					Details:  map[string]any{"codes_remaining": remaining},
				})
			}
			if remaining <= 2 {
				slog.WarnContext(ctx, "mfa-verify: recovery codes running low", "user_id", claims.UserID, "remaining", remaining)
			}
		} else if err == nil {
			if srv.eventWriter != nil {
				srv.eventWriter.Write(ctx, secure.Event{
					Type:     secure.EventMFARecoveryCodeFailed,
					Severity: secure.SeverityWarning,
					ActorIP:  clientIP(ctx),
					UserID:   &claims.UserID,
				})
			}
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
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAVerifyFailed,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &claims.UserID,
				Details:  map[string]any{"method": input.Body.Method},
			})
		}
		return nil, huma.Error401Unauthorized("invalid verification code")
	}

	// MFA verified — clear lockout counter.
	srv.lockout.RecordSuccess(ctx, user.Email)

	// Emit success event.
	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAVerifySuccess,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &claims.UserID,
			Details:  map[string]any{"method": input.Body.Method},
		})
	}

	// Progress the pending token.
	remaining := removePendingItem(claims.Pending, "mfa_challenge")

	out := &mfaVerifyOutput{}
	out.Body.UserID = claims.UserID

	if len(remaining) > 0 {
		// More steps needed — reissue pending token with remaining items.
		secret := srv.jwtSecret()
		// Methods are no longer relevant after MFA challenge is cleared.
		pendingToken, ptErr := auth.IssuePendingToken(
			secret, claims.UserID, claims.TokenVersion,
			remaining, nil, claims.Reasons, srv.cfg.MFAPendingTokenTTL,
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
			if srv.eventWriter != nil {
				srv.eventWriter.Write(ctx, secure.Event{
					Type:     secure.EventMFARememberDeviceIssued,
					Severity: secure.SeverityInfo,
					ActorIP:  clientIP(ctx),
					UserID:   &claims.UserID,
				})
			}
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
	claims, err := auth.ParsePendingToken(tokenStr, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
	if err != nil {
		return nil, err
	}
	if len(claims.Pending) == 0 || claims.Pending[0] != expectedStep {
		return nil, fmt.Errorf("unexpected pending step: want %s, got %v", expectedStep, claims.Pending)
	}
	return claims, nil
}

// reissuePendingTokenCookies reissues the pending token with a fresh TTL.
func (srv *Server) reissuePendingTokenCookies(claims *auth.PendingClaims) ([]string, error) {
	secret := srv.jwtSecret()
	token, err := auth.IssuePendingToken(
		secret, claims.UserID, claims.TokenVersion,
		claims.Pending, claims.Methods, claims.Reasons, srv.cfg.MFAPendingTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("reissue pending token: %w", err)
	}
	return pendingTokenCookies(token, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL), nil
}

// issueFullAuthTokens creates and returns access + refresh token cookies.
func (srv *Server) issueFullAuthTokens(ctx context.Context, user *generated.User) ([]string, error) {
	secret := srv.jwtSecret()
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
	secretBytes, err := crypto.DecryptWithFallback(encKey, prevKey, cred.SecretEnc, userID[:])
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	// Validate the TOTP code. Capture time once to prevent clock-boundary
	// race between validation and replay-prevention step calculation.
	now := time.Now()
	valid, err := totp.ValidateCustom(code, string(secretBytes), now, totpValidateOpts)
	if err != nil {
		return false, fmt.Errorf("validate TOTP: %w", err)
	}
	if !valid {
		return false, nil
	}

	// Atomic replay prevention with FOR UPDATE lock.
	// Store maxStep = currentStep + skew to block replays across the entire acceptance window.
	maxStep := (now.Unix() / 30) + int64(totpValidateOpts.Skew) //nolint:gosec // G115: Skew is a small constant (1), no overflow risk
	fresh, stepErr := srv.store.VerifyAndUpdateTOTPStep(ctx, userID, maxStep)
	if stepErr != nil {
		return false, fmt.Errorf("totp step check: %w", stepErr)
	}
	if !fresh {
		return false, nil // replay
	}

	return true, nil
}

// verifyEmailOTP validates an email OTP code against the active challenge.
func (srv *Server) verifyEmailOTP(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	codeHash := sha256Hex(code)
	maxAttempts := int32(srv.cfg.MFAChallengeMaxAttempts) //nolint:gosec // G115: config value, bounded by env default (3)
	matched, exhausted, err := srv.store.VerifyEmailOTPChallenge(ctx, userID, codeHash, maxAttempts)
	if err != nil {
		return false, err
	}
	if exhausted && srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAChallengeExhausted,
			Severity: secure.SeverityWarning,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
		})
	}
	return matched, nil
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

// ── TOTP Enrollment ──────────────────────────────────────────────────────────

type mfaTOTPSetupInput struct {
	AccessToken     string `cookie:"access_token"`
	MFAPendingToken string `cookie:"mfa_pending_token"`
}

type mfaTOTPSetupOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		QRCodeURI string `json:"qr_code_uri" doc:"otpauth:// URI for QR code"`
		Secret    string `json:"secret"      doc:"Base32-encoded TOTP secret (manual entry)"`
	}
}

// mfaTOTPSetupHandler handles POST /auth/mfa/totp/setup.
// Generates a TOTP secret/QR URI and stores the encrypted secret in a
// short-lived enrollment cookie. The secret is NOT persisted to the DB
// until the user confirms with a valid code.
func (srv *Server) mfaTOTPSetupHandler(ctx context.Context, input *mfaTOTPSetupInput) (*mfaTOTPSetupOutput, error) {
	userID, err := srv.resolveEnrollmentUserID(ctx, input.AccessToken, input.MFAPendingToken)
	if err != nil {
		return nil, err
	}

	// Check not already enrolled.
	if err := srv.checkNotAlreadyEnrolled(ctx, userID, "totp", "totp-setup"); err != nil {
		return nil, err
	}

	// Look up user email for the TOTP account name.
	user, err := srv.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "totp-setup: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Generate TOTP key.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CVErt Ops",
		AccountName: user.Email,
		Period:      30,
		SecretSize:  20,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		slog.ErrorContext(ctx, "totp-setup: generate key", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Validate URI round-trip (design doc requirement).
	parsed, err := otp.NewKeyFromURL(key.URL())
	if err != nil || parsed.Secret() != key.Secret() {
		slog.ErrorContext(ctx, "totp-setup: URI round-trip failed")
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Encrypt secret for enrollment cookie.
	encKey, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(ctx, "totp-setup: encryption key", "error", err)
		return nil, huma.Error500InternalServerError("encryption key not configured")
	}
	secretEnc, err := crypto.Encrypt(encKey, []byte(key.Secret()), userID[:])
	if err != nil {
		slog.ErrorContext(ctx, "totp-setup: encrypt secret", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Issue enrollment token (short-lived JWT containing encrypted secret).
	jwtSecret := srv.jwtSecret()
	enrollToken, err := auth.IssueEnrollmentToken(jwtSecret, userID, secretEnc, enrollmentTokenTTL)
	if err != nil {
		slog.ErrorContext(ctx, "totp-setup: issue enrollment token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	out := &mfaTOTPSetupOutput{}
	out.Body.QRCodeURI = key.URL()
	out.Body.Secret = key.Secret()
	out.SetCookie = enrollmentTokenCookies(enrollToken, srv.cfg.CookieSecure)
	return out, nil
}

type mfaTOTPConfirmInput struct {
	AccessToken     string `cookie:"access_token"`
	MFAPendingToken string `cookie:"mfa_pending_token"`
	MFAEnrollToken  string `cookie:"mfa_enroll_token"`
	Body            struct {
		Code string `json:"code" minLength:"6" maxLength:"6" doc:"6-digit TOTP code from authenticator app"`
	}
}

type mfaTOTPConfirmOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		RecoveryCodes []string `json:"recovery_codes,omitempty" doc:"One-time recovery codes (only on first MFA enrollment)"`
	}
}

// mfaTOTPConfirmHandler handles POST /auth/mfa/totp/confirm.
// Validates the TOTP code against the provisional secret from the enrollment
// cookie, then persists the credential and generates recovery codes.
func (srv *Server) mfaTOTPConfirmHandler(ctx context.Context, input *mfaTOTPConfirmInput) (*mfaTOTPConfirmOutput, error) {
	userID, err := srv.resolveEnrollmentUserID(ctx, input.AccessToken, input.MFAPendingToken)
	if err != nil {
		return nil, err
	}

	// Parse enrollment token.
	if input.MFAEnrollToken == "" {
		return nil, huma.Error401Unauthorized("enrollment token required — call setup first")
	}
	enrollClaims, err := auth.ParseEnrollmentToken(input.MFAEnrollToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired enrollment token")
	}
	if enrollClaims.UserID != userID {
		return nil, huma.Error401Unauthorized("enrollment token user mismatch")
	}

	// Decrypt the provisional secret.
	encKey, err := srv.ssoEncryptionKey()
	if err != nil {
		slog.ErrorContext(ctx, "totp-confirm: encryption key", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	prevKey := srv.ssoEncryptionKeyPrevious()
	secretBytes, err := crypto.DecryptWithFallback(encKey, prevKey, enrollClaims.SecretEnc, userID[:])
	if err != nil {
		slog.ErrorContext(ctx, "totp-confirm: decrypt secret", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Validate the TOTP code against the provisional secret.
	valid, err := totp.ValidateCustom(input.Body.Code, string(secretBytes), time.Now(), totpValidateOpts)
	if err != nil {
		slog.ErrorContext(ctx, "totp-confirm: validate code", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !valid {
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAEnrollmentFailed,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &userID,
				Details:  map[string]any{"method": "totp", "reason": "invalid_code"},
			})
		}
		return nil, huma.Error401Unauthorized("invalid TOTP code")
	}

	// Check not already enrolled (race condition guard).
	if err := srv.checkNotAlreadyEnrolled(ctx, userID, "totp", "totp-confirm"); err != nil {
		return nil, err
	}

	// Re-encrypt secret for DB storage (enrollment cookie used same key, but
	// re-encrypt to get a fresh nonce for defense in depth).
	secretEncDB, err := crypto.Encrypt(encKey, secretBytes, userID[:])
	if err != nil {
		slog.ErrorContext(ctx, "totp-confirm: re-encrypt secret", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Persist the credential.
	if _, err := srv.store.CreateMFACredential(ctx, userID, "totp", secretEncDB); err != nil {
		slog.ErrorContext(ctx, "totp-confirm: create credential", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAMethodEnrolled,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
			Details:  map[string]any{"method": "totp"},
		})
	}

	out := &mfaTOTPConfirmOutput{}

	// Generate recovery codes on first enrollment (non-fatal).
	out.Body.RecoveryCodes = srv.generateFirstEnrollmentRecoveryCodes(ctx, userID, "totp-confirm")

	// Clear enrollment cookie.
	out.SetCookie = []string{clearEnrollmentCookie(srv.cfg.CookieSecure)}

	// If this was a restricted enrollment session, clear mfa_enrollment_required.
	if input.MFAPendingToken != "" {
		cookies, clearErr := srv.clearEnrollmentPending(ctx, input.MFAPendingToken)
		if clearErr != nil {
			slog.ErrorContext(ctx, "totp-confirm: clear enrollment pending", "error", clearErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.SetCookie = append(out.SetCookie, cookies...)
	}

	return out, nil
}

// ── Email OTP Enrollment ─────────────────────────────────────────────────────

type mfaEmailOTPSetupInput struct {
	AccessToken     string `cookie:"access_token"`
	MFAPendingToken string `cookie:"mfa_pending_token"`
}

type mfaEmailOTPSetupOutput struct {
	SetCookie []string `header:"Set-Cookie"`
}

// mfaEmailOTPSetupHandler handles POST /auth/mfa/email-otp/setup.
// Sends a verification code to the user's email address.
func (srv *Server) mfaEmailOTPSetupHandler(ctx context.Context, input *mfaEmailOTPSetupInput) (*mfaEmailOTPSetupOutput, error) {
	userID, err := srv.resolveEnrollmentUserID(ctx, input.AccessToken, input.MFAPendingToken)
	if err != nil {
		return nil, err
	}

	// Check not already enrolled.
	if err := srv.checkNotAlreadyEnrolled(ctx, userID, "email_otp", "email-otp-setup"); err != nil {
		return nil, err
	}

	user, err := srv.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "email-otp-setup: get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Rate-limit email OTP codes per hour.
	since := time.Now().Add(-1 * time.Hour)
	count, countErr := srv.store.CountRecentEmailOTPChallenges(ctx, userID, since)
	if countErr != nil {
		slog.ErrorContext(ctx, "email-otp-setup: count recent", "error", countErr)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if count >= int64(srv.cfg.MFAEmailOTPMaxPerHour) {
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAEmailOTPRateLimited,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &userID,
			})
		}
		return nil, huma.Error429TooManyRequests("too many email OTP requests — try again later")
	}

	// Generate and store OTP code.
	code, err := generateEmailOTPCode()
	if err != nil {
		slog.ErrorContext(ctx, "email-otp-setup: generate code", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	codeHash := sha256Hex(code)
	expiresAt := time.Now().Add(srv.cfg.MFAEmailOTPTTL)
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, codeHash, expiresAt); err != nil {
		slog.ErrorContext(ctx, "email-otp-setup: create challenge", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Send the code.
	if err := srv.sendMFAOTPEmail(ctx, user.Email, code); err != nil {
		slog.WarnContext(ctx, "email-otp-setup: send email", "error", err)
	}

	out := &mfaEmailOTPSetupOutput{}

	// Reissue the pending token with fresh TTL to prevent expiry during setup-confirm window.
	if input.MFAPendingToken != "" {
		claims, parseErr := auth.ParsePendingToken(input.MFAPendingToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
		if parseErr == nil {
			cookies, reissueErr := srv.reissuePendingTokenCookies(claims)
			if reissueErr != nil {
				slog.ErrorContext(ctx, "email-otp-setup: reissue pending token", "error", reissueErr)
			} else {
				out.SetCookie = append(out.SetCookie, cookies...)
			}
		}
	}

	return out, nil
}

type mfaEmailOTPConfirmInput struct {
	AccessToken     string `cookie:"access_token"`
	MFAPendingToken string `cookie:"mfa_pending_token"`
	Body            struct {
		Code string `json:"code" minLength:"6" maxLength:"6" doc:"6-digit code from email"`
	}
}

type mfaEmailOTPConfirmOutput struct {
	SetCookie []string `header:"Set-Cookie"`
	Body      struct {
		RecoveryCodes []string `json:"recovery_codes,omitempty" doc:"One-time recovery codes (only on first MFA enrollment)"`
	}
}

// mfaEmailOTPConfirmHandler handles POST /auth/mfa/email-otp/confirm.
// Verifies the email OTP code and creates the email_otp credential.
func (srv *Server) mfaEmailOTPConfirmHandler(ctx context.Context, input *mfaEmailOTPConfirmInput) (*mfaEmailOTPConfirmOutput, error) {
	userID, err := srv.resolveEnrollmentUserID(ctx, input.AccessToken, input.MFAPendingToken)
	if err != nil {
		return nil, err
	}

	// Check not already enrolled.
	if err := srv.checkNotAlreadyEnrolled(ctx, userID, "email_otp", "email-otp-confirm"); err != nil {
		return nil, err
	}

	// Verify the code.
	codeHash := sha256Hex(input.Body.Code)
	maxAttempts := int32(srv.cfg.MFAChallengeMaxAttempts) //nolint:gosec // G115: config value, bounded by env default (3)
	matched, exhausted, err := srv.store.VerifyEmailOTPChallenge(ctx, userID, codeHash, maxAttempts)
	if err != nil {
		slog.ErrorContext(ctx, "email-otp-confirm: verify", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if exhausted && srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAChallengeExhausted,
			Severity: secure.SeverityWarning,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
		})
	}
	if !matched {
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAEnrollmentFailed,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &userID,
				Details:  map[string]any{"method": "email_otp", "reason": "invalid_code"},
			})
		}
		return nil, huma.Error401Unauthorized("invalid verification code")
	}

	// Persist the credential (no secret for email OTP).
	if _, err := srv.store.CreateMFACredential(ctx, userID, "email_otp", nil); err != nil {
		slog.ErrorContext(ctx, "email-otp-confirm: create credential", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAMethodEnrolled,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
			Details:  map[string]any{"method": "email_otp"},
		})
	}

	out := &mfaEmailOTPConfirmOutput{}

	// Generate recovery codes on first enrollment (non-fatal).
	out.Body.RecoveryCodes = srv.generateFirstEnrollmentRecoveryCodes(ctx, userID, "email-otp-confirm")

	// If this was a restricted enrollment session, clear mfa_enrollment_required.
	if input.MFAPendingToken != "" {
		cookies, clearErr := srv.clearEnrollmentPending(ctx, input.MFAPendingToken)
		if clearErr != nil {
			slog.ErrorContext(ctx, "email-otp-confirm: clear enrollment pending", "error", clearErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		out.SetCookie = cookies
	}

	return out, nil
}

// ── MFA Management ───────────────────────────────────────────────────────────

type mfaMethodsInput struct {
	AccessToken string `cookie:"access_token"`
}

type mfaMethodEntry struct {
	Method    string    `json:"method"     doc:"MFA method name (totp, email_otp)"`
	CreatedAt time.Time `json:"created_at" doc:"When this method was enrolled"`
}

type mfaMethodsOutput struct {
	Body struct {
		Methods                []mfaMethodEntry         `json:"methods"`
		RecoveryCodesRemaining int                      `json:"recovery_codes_remaining"`
		Required               bool                     `json:"required"          doc:"Whether MFA is required for this user"`
		RequiredReasons        []auth.MFARequiredReason `json:"required_reasons"  doc:"Why MFA is required"`
	}
}

// mfaMethodsHandler handles GET /auth/mfa/methods.
// Returns enrolled MFA methods, recovery code count, and enforcement status.
func (srv *Server) mfaMethodsHandler(ctx context.Context, input *mfaMethodsInput) (*mfaMethodsOutput, error) {
	userID, err := srv.resolveAccessTokenUserID(input.AccessToken)
	if err != nil {
		return nil, err
	}

	creds, err := srv.store.GetMFACredentialsByUserID(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "mfa-methods: get credentials", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	remaining, err := srv.store.CountUnusedRecoveryCodes(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "mfa-methods: count recovery codes", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	reasons := srv.buildMFARequiredReasons(ctx, userID)

	out := &mfaMethodsOutput{}
	out.Body.Methods = make([]mfaMethodEntry, len(creds))
	for i, c := range creds {
		out.Body.Methods[i] = mfaMethodEntry{
			Method:    c.Method,
			CreatedAt: c.CreatedAt,
		}
	}
	out.Body.RecoveryCodesRemaining = int(remaining)
	out.Body.Required = len(reasons) > 0
	out.Body.RequiredReasons = reasons
	return out, nil
}

type mfaRemoveMethodInput struct {
	AccessToken string `cookie:"access_token"`
	Method      string `path:"method" enum:"totp,email_otp" doc:"MFA method to remove"`
	Body        struct {
		CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password for re-authentication"`
	}
}

// mfaRemoveMethodHandler handles DELETE /auth/mfa/methods/{method}.
// Removes an MFA method after password re-authentication. Blocks removal
// of the last method when MFA is mandated.
func (srv *Server) mfaRemoveMethodHandler(ctx context.Context, input *mfaRemoveMethodInput) (*struct{}, error) {
	userID, err := srv.resolveAccessTokenUserID(input.AccessToken)
	if err != nil {
		return nil, err
	}

	// Re-authenticate with current password.
	if _, err := srv.reauthenticatePassword(ctx, userID, input.Body.CurrentPassword, "mfa-remove"); err != nil {
		return nil, err
	}

	// Check if this is the last method and MFA is mandated.
	credCount, err := srv.store.CountMFACredentialsByUser(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "mfa-remove: count credentials", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if credCount <= 1 {
		isSiteAdmin, saErr := srv.store.IsSiteAdmin(ctx, userID)
		if saErr != nil {
			slog.ErrorContext(ctx, "mfa-remove: check site admin", "error", saErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		mfaCfg := store.MFAConfig{
			RequiredSiteAdmins: srv.cfg.MFARequiredSiteAdmins,
			RequiredOrgOwners:  srv.cfg.MFARequiredOrgOwners,
		}
		required, reqErr := srv.store.UserMFARequired(ctx, userID, isSiteAdmin, mfaCfg)
		if reqErr != nil {
			slog.ErrorContext(ctx, "mfa-remove: check mandate", "error", reqErr)
			return nil, huma.Error500InternalServerError("internal error")
		}
		if required {
			if srv.eventWriter != nil {
				srv.eventWriter.Write(ctx, secure.Event{
					Type:     secure.EventMFADisableBlocked,
					Severity: secure.SeverityWarning,
					ActorIP:  clientIP(ctx),
					UserID:   &userID,
					Details:  map[string]any{"method": input.Method},
				})
			}
			return nil, huma.Error403Forbidden("MFA is required and cannot be disabled")
		}
	}

	// Delete the method.
	deleted, err := srv.store.DeleteMFACredential(ctx, userID, input.Method)
	if err != nil {
		slog.ErrorContext(ctx, "mfa-remove: delete credential", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if deleted == 0 {
		return nil, huma.Error404NotFound("method not enrolled")
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFAMethodRemoved,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
			Details:  map[string]any{"method": input.Method},
		})
	}

	// If no remaining credentials, delete recovery codes too.
	remaining, err := srv.store.CountMFACredentialsByUser(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "mfa-remove: count remaining", "error", err)
	} else if remaining == 0 {
		if err := srv.store.DeleteAllRecoveryCodes(ctx, userID); err != nil {
			slog.WarnContext(ctx, "mfa-remove: delete recovery codes", "error", err)
		}
		// Also delete remember-device tokens.
		if err := srv.store.DeleteRememberDeviceTokens(ctx, userID); err != nil {
			slog.WarnContext(ctx, "mfa-remove: delete device tokens", "error", err)
		}
		if srv.eventWriter != nil {
			srv.eventWriter.Write(ctx, secure.Event{
				Type:     secure.EventMFAAllMethodsRemoved,
				Severity: secure.SeverityWarning,
				ActorIP:  clientIP(ctx),
				UserID:   &userID,
			})
		}
	}

	return nil, nil
}

// ── Recovery Code Regeneration ───────────────────────────────────────────────

type mfaRegenerateCodesInput struct {
	AccessToken string `cookie:"access_token"`
	Body        struct {
		CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password for re-authentication"`
	}
}

type mfaRegenerateCodesOutput struct {
	Body struct {
		RecoveryCodes []string `json:"recovery_codes" doc:"10 new one-time recovery codes"`
	}
}

// mfaRegenerateCodesHandler handles POST /auth/mfa/recovery-codes/regenerate.
// Requires active MFA enrollment and password re-authentication.
func (srv *Server) mfaRegenerateCodesHandler(ctx context.Context, input *mfaRegenerateCodesInput) (*mfaRegenerateCodesOutput, error) {
	userID, err := srv.resolveAccessTokenUserID(input.AccessToken)
	if err != nil {
		return nil, err
	}

	// Verify user has MFA enrolled.
	hasMFA, err := srv.store.UserHasMFACredentials(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "recovery-regen: check MFA", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !hasMFA {
		return nil, huma.Error409Conflict("no MFA methods enrolled")
	}

	// Re-authenticate with current password.
	if _, err := srv.reauthenticatePassword(ctx, userID, input.Body.CurrentPassword, "recovery-regen"); err != nil {
		return nil, err
	}

	// Regenerate codes (deletes old, creates new).
	codes, err := srv.store.RegenerateRecoveryCodes(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "recovery-regen: regenerate", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFARecoveryCodesGenerated,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
		})
	}

	out := &mfaRegenerateCodesOutput{}
	out.Body.RecoveryCodes = codes
	return out, nil
}

// ── Password Re-Auth ─────────────────────────────────────────────────────────

// reauthenticatePassword verifies the user's current password using the
// argon2 semaphore. Returns the user on success, or an appropriate huma error.
func (srv *Server) reauthenticatePassword(ctx context.Context, userID uuid.UUID, password, logPrefix string) (*generated.User, error) {
	user, err := srv.store.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, logPrefix+": get user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !user.PasswordHash.Valid {
		return nil, huma.Error400BadRequest("account uses OAuth — password re-auth not available")
	}
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	var pwOK bool
	func() {
		defer srv.releaseArgon2()
		pwOK, err = auth.VerifyPassword(password, user.PasswordHash.String)
	}()
	if err != nil {
		slog.ErrorContext(ctx, logPrefix+": verify password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if !pwOK {
		return nil, huma.Error401Unauthorized("current password incorrect")
	}
	return user, nil
}

// checkNotAlreadyEnrolled returns an error if the user already has a credential
// for the given method. Returns nil if enrollment can proceed.
func (srv *Server) checkNotAlreadyEnrolled(ctx context.Context, userID uuid.UUID, method, logPrefix string) error {
	existing, err := srv.store.GetMFACredentialByUserAndMethod(ctx, userID, method)
	if err != nil {
		slog.ErrorContext(ctx, logPrefix+": check existing", "error", err)
		return huma.Error500InternalServerError("internal error")
	}
	if existing != nil {
		return huma.Error409Conflict(method + " already enrolled")
	}
	return nil
}

// generateFirstEnrollmentRecoveryCodes generates recovery codes if this is the
// user's first MFA enrollment (credential count == 1). Returns the codes, or
// nil if this isn't the first enrollment or if generation fails (non-fatal).
func (srv *Server) generateFirstEnrollmentRecoveryCodes(ctx context.Context, userID uuid.UUID, logPrefix string) []string {
	credCount, countErr := srv.store.CountMFACredentialsByUser(ctx, userID)
	if countErr != nil {
		slog.ErrorContext(ctx, logPrefix+": count credentials", "error", countErr)
		return nil
	}
	if credCount != 1 {
		return nil
	}
	codes, err := srv.store.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, logPrefix+": generate recovery codes", "error", err)
		return nil
	}
	if srv.eventWriter != nil {
		srv.eventWriter.Write(ctx, secure.Event{
			Type:     secure.EventMFARecoveryCodesGenerated,
			Severity: secure.SeverityInfo,
			ActorIP:  clientIP(ctx),
			UserID:   &userID,
		})
	}
	return codes
}

// ── Enrollment/Management Helpers ────────────────────────────────────────────

// resolveEnrollmentUserID extracts the user ID from either an access token
// or a pending enrollment token. Returns 401 if neither is valid.
func (srv *Server) resolveEnrollmentUserID(ctx context.Context, accessToken, pendingToken string) (uuid.UUID, error) {
	secret := srv.jwtSecret()

	// Try access token first (fully authenticated user).
	if accessToken != "" {
		claims, err := auth.ParseAccessToken(accessToken, secret, srv.jwtPreviousSecretBytes())
		if err == nil {
			return claims.UserID, nil
		}
	}

	// Fall back to pending enrollment token.
	if pendingToken != "" {
		claims, err := auth.ParsePendingToken(pendingToken, secret, srv.jwtPreviousSecretBytes())
		if err == nil && len(claims.Pending) > 0 && claims.Pending[0] == "mfa_enrollment_required" {
			// Validate token_version against DB (prevents stale tokens after admin actions).
			user, err := srv.store.GetUserByID(ctx, claims.UserID)
			if err != nil || user == nil {
				return uuid.Nil, huma.Error401Unauthorized("authentication required")
			}
			if int(user.TokenVersion) != claims.TokenVersion {
				return uuid.Nil, huma.Error401Unauthorized("session invalidated — please log in again")
			}
			return claims.UserID, nil
		}
	}

	return uuid.Nil, huma.Error401Unauthorized("authentication required")
}

// resolveAccessTokenUserID extracts the user ID from an access token only.
// Used by management endpoints that require full authentication.
func (srv *Server) resolveAccessTokenUserID(accessToken string) (uuid.UUID, error) {
	if accessToken == "" {
		return uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(accessToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
	if err != nil {
		return uuid.Nil, huma.Error401Unauthorized("invalid or expired access token")
	}
	return claims.UserID, nil
}

// enrollmentTokenCookies creates the mfa_enroll_token Set-Cookie header.
func enrollmentTokenCookies(token string, secure bool) []string {
	c := &http.Cookie{
		Name:     "mfa_enroll_token",
		Value:    token,
		Path:     "/api/v1/auth/mfa",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(enrollmentTokenTTL.Seconds()),
	}
	return []string{c.String()}
}

// clearEnrollmentCookie expires the mfa_enroll_token cookie.
func clearEnrollmentCookie(secure bool) string {
	c := &http.Cookie{
		Name:     "mfa_enroll_token",
		Value:    "",
		Path:     "/api/v1/auth/mfa",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	return c.String()
}

// clearEnrollmentPending removes "mfa_enrollment_required" from the pending
// token and reissues it. If no items remain, issues full auth tokens.
func (srv *Server) clearEnrollmentPending(ctx context.Context, pendingToken string) ([]string, error) {
	claims, err := auth.ParsePendingToken(pendingToken, srv.jwtSecret(), srv.jwtPreviousSecretBytes())
	if err != nil {
		return nil, fmt.Errorf("parse pending token: %w", err)
	}
	remaining := removePendingItem(claims.Pending, "mfa_enrollment_required")
	if len(remaining) > 0 {
		secret := srv.jwtSecret()
		token, err := auth.IssuePendingToken(secret, claims.UserID, claims.TokenVersion, remaining, nil, claims.Reasons, srv.cfg.MFAPendingTokenTTL)
		if err != nil {
			slog.ErrorContext(ctx, "mfa: reissue pending after enrollment", "error", err)
			return nil, fmt.Errorf("reissue pending token: %w", err)
		}
		return pendingTokenCookies(token, srv.cfg.CookieSecure, srv.cfg.MFAPendingTokenTTL), nil
	}

	// All pending items cleared — issue full auth tokens.
	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "mfa: enrollment complete, re-read user", "error", err)
		return nil, fmt.Errorf("re-read user: %w", err)
	}
	authCookies, tokErr := srv.issueFullAuthTokens(ctx, user)
	if tokErr != nil {
		return nil, tokErr
	}
	// Clear both enrollment and pending cookies, add auth cookies.
	cookies := append(authCookies, clearPendingTokenCookie(srv.cfg.CookieSecure))
	return cookies, nil
}

// buildMFARequiredReasons returns the list of reasons why MFA is required
// for this user (empty if not required). Fail-closed: DB errors add a
// "db_error" reason so MFA appears mandatory when status is unknown.
func (srv *Server) buildMFARequiredReasons(ctx context.Context, userID uuid.UUID) []auth.MFARequiredReason {
	var reasons []auth.MFARequiredReason
	var dbErr bool

	isSiteAdmin, err := srv.store.IsSiteAdmin(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "mfa-reasons: check site admin", "error", err)
		dbErr = true
	}

	if srv.cfg.MFARequiredSiteAdmins && isSiteAdmin {
		reasons = append(reasons, auth.MFARequiredReason{Source: "site_admin"})
	}

	if srv.cfg.MFARequiredOrgOwners {
		isOwner, err := srv.store.IsOrgOwner(ctx, userID)
		if err != nil {
			slog.WarnContext(ctx, "mfa-reasons: check org owner", "error", err)
			dbErr = true
		}
		if isOwner {
			reasons = append(reasons, auth.MFARequiredReason{Source: "org_owner"})
		}
	}

	orgPolicyNames, err := srv.store.UserMFARequiredOrgNames(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "mfa-reasons: check org-wide", "error", err)
		dbErr = true
	}
	for _, name := range orgPolicyNames {
		reasons = append(reasons, auth.MFARequiredReason{Source: "org_policy", OrgName: name})
	}

	perMemberNames, err := srv.store.UserMFARequirementOrgNames(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "mfa-reasons: check per-member", "error", err)
		dbErr = true
	}
	for _, name := range perMemberNames {
		reasons = append(reasons, auth.MFARequiredReason{Source: "per_member", OrgName: name})
	}

	// Fail-closed: if any DB check failed and no explicit reason was found,
	// report MFA as required so the UI doesn't show "not required" when we
	// can't determine the real status.
	if dbErr && len(reasons) == 0 {
		reasons = append(reasons, auth.MFARequiredReason{Source: "db_error"})
	}

	return reasons
}

// ── Route registration ────────────────────────────────────────────────────────

// registerMFARoutes registers MFA challenge, verify, enrollment, and management routes.
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

	// TOTP enrollment.
	huma.Register(api, huma.Operation{
		OperationID:   "mfa-totp-setup",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/totp/setup",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Generate TOTP secret and QR code URI",
		DefaultStatus: http.StatusOK,
	}, srv.mfaTOTPSetupHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "mfa-totp-confirm",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/totp/confirm",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Verify TOTP code and finalize enrollment",
		DefaultStatus: http.StatusOK,
	}, srv.mfaTOTPConfirmHandler)

	// Email OTP enrollment.
	huma.Register(api, huma.Operation{
		OperationID:   "mfa-email-otp-setup",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/email-otp/setup",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Send email OTP verification code for enrollment",
		DefaultStatus: http.StatusOK,
	}, srv.mfaEmailOTPSetupHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "mfa-email-otp-confirm",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/email-otp/confirm",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Verify email OTP code and finalize enrollment",
		DefaultStatus: http.StatusOK,
	}, srv.mfaEmailOTPConfirmHandler)

	// MFA management.
	huma.Register(api, huma.Operation{
		OperationID:   "mfa-methods-list",
		Method:        http.MethodGet,
		Path:          "/auth/mfa/methods",
		Tags:          []string{"auth", "mfa"},
		Summary:       "List enrolled MFA methods and enforcement status",
		DefaultStatus: http.StatusOK,
	}, srv.mfaMethodsHandler)

	huma.Register(api, huma.Operation{
		OperationID:   "mfa-method-remove",
		Method:        http.MethodDelete,
		Path:          "/auth/mfa/methods/{method}",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Remove an MFA method (requires password re-auth)",
		DefaultStatus: http.StatusNoContent,
	}, srv.mfaRemoveMethodHandler)

	// Recovery code regeneration.
	huma.Register(api, huma.Operation{
		OperationID:   "mfa-recovery-codes-regenerate",
		Method:        http.MethodPost,
		Path:          "/auth/mfa/recovery-codes/regenerate",
		Tags:          []string{"auth", "mfa"},
		Summary:       "Regenerate recovery codes (requires password re-auth)",
		DefaultStatus: http.StatusOK,
	}, srv.mfaRegenerateCodesHandler)
}
