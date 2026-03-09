// ABOUTME: HTTP handlers for password reset: forgot-password and reset-password.
// ABOUTME: Public endpoints at /api/v1/auth/forgot-password and /api/v1/auth/reset-password.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/notify"
)

// formatTTL converts a duration to a human-readable string for email templates.
func formatTTL(d time.Duration) string {
	if h := int(d.Hours()); h >= 24 && h%24 == 0 {
		days := h / 24
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}
	if h := int(d.Hours()); h > 0 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	m := int(d.Minutes())
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// ── Forgot Password ────────────────────────────────────────────────────────────

// forgotPasswordInput is the request body for POST /auth/forgot-password.
type forgotPasswordInput struct {
	Body struct {
		Email string `json:"email" format:"email" maxLength:"254" doc:"Email address"`
	}
}

// forgotPasswordOutput always returns 200 regardless of whether the email exists.
type forgotPasswordOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

// forgotPasswordResponse is the constant response for all forgot-password outcomes.
// Every path (unknown user, rate-limited, success) returns this to prevent email enumeration.
const forgotPasswordResponse = "If an account with that email exists, a password reset link has been sent." //nolint:gosec // G101 false positive: user-facing response message, not a credential

// forgotPasswordHandler handles POST /api/v1/auth/forgot-password.
// Always returns 200 to prevent email enumeration. Email delivery is async
// so all paths have indistinguishable response times.
func (srv *Server) forgotPasswordHandler(ctx context.Context, input *forgotPasswordInput) (*forgotPasswordOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	out := &forgotPasswordOutput{Body: struct {
		Message string `json:"message"`
	}{Message: forgotPasswordResponse}}

	user, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		// Return 200 even on DB error to preserve the anti-enumeration invariant.
		// A 500 here would reveal whether the code path reached the DB lookup
		// (which depends on the email format being valid).
		slog.ErrorContext(ctx, "forgot-password: lookup email", "error", err)
		return out, nil
	}

	// Unknown user or OAuth-only account — return identical 200.
	// Burn a small amount of CPU (token gen + hash) to normalize timing against
	// the token-creation path. The significant gap (SMTP) is eliminated by
	// making email delivery async on all paths.
	if user == nil || !user.PasswordHash.Valid {
		dummyBytes := make([]byte, 32)
		_, _ = rand.Read(dummyBytes)
		_ = sha256.Sum256(dummyBytes)
		return out, nil
	}

	// Per-user rate limit: silently drop excess requests (returning 200).
	// A distinct status code here would confirm the email is registered.
	// Accepted risk (A10): the count-then-insert pattern has a TOCTOU race under
	// concurrent requests, but the blast radius is bounded by the IP rate limiter
	// (10/min) and all tokens go to the same legitimate email.
	count, err := srv.store.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		// Return 200 to preserve anti-enumeration invariant — a 500 only on this
		// path would confirm the email is registered.
		slog.ErrorContext(ctx, "forgot-password: count recent tokens", "error", err)
		return out, nil
	}
	if int(count) >= srv.cfg.PasswordResetMaxPerHour {
		return out, nil
	}

	// Generate 32-byte random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.ErrorContext(ctx, "forgot-password: generate token", "error", err)
		return out, nil
	}
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(srv.cfg.PasswordResetTokenTTL)

	if err := srv.store.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		slog.ErrorContext(ctx, "forgot-password: create token", "error", err)
		return out, nil
	}

	// Deliver email asynchronously so response time doesn't leak user existence.
	// context.WithoutCancel: email delivery must survive the HTTP response.
	bgCtx := context.WithoutCancel(ctx)
	email := user.Email
	ttl := srv.cfg.PasswordResetTokenTTL
	go func() {
		resetURL := srv.cfg.ExternalURL + "/reset-password?token=" + tokenHex
		subject, htmlBody, textBody, renderErr := notify.RenderPasswordReset(notify.PasswordResetData{
			Email:     email,
			ResetURL:  resetURL,
			ExpiresIn: formatTTL(ttl),
		})
		if renderErr != nil {
			slog.ErrorContext(bgCtx, "forgot-password: render email", "error", renderErr)
			return
		}
		smtpCfg := notify.SmtpConfig{
			Host:     srv.cfg.SMTPHost,
			Port:     srv.cfg.SMTPPort,
			From:     srv.cfg.SMTPFrom,
			Username: srv.cfg.SMTPUsername,
			Password: srv.cfg.SMTPPassword,
			TLS:      srv.cfg.SMTPTLS,
		}
		if emailErr := notify.EmailSend(bgCtx, smtpCfg, []string{email}, subject, htmlBody, textBody); emailErr != nil {
			slog.WarnContext(bgCtx, "forgot-password: send email failed", "email", email, "error", emailErr)
		}
	}()

	return out, nil
}

// ── Reset Password ─────────────────────────────────────────────────────────────

// resetPasswordInput is the request body for POST /auth/reset-password.
type resetPasswordInput struct {
	Body struct {
		Token       string `json:"token"        minLength:"1"  doc:"Password reset token (hex-encoded)"`
		NewPassword string `json:"new_password" minLength:"16" maxLength:"1024" doc:"New password (min 16 characters)"`
	}
}

// resetPasswordOutput has no body — 200 on success.
type resetPasswordOutput struct{}

// resetPasswordHandler handles POST /api/v1/auth/reset-password.
func (srv *Server) resetPasswordHandler(ctx context.Context, input *resetPasswordInput) (*resetPasswordOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	// Decode and hash the token.
	tokenBytes, decodeErr := hex.DecodeString(input.Body.Token)
	if decodeErr != nil || len(tokenBytes) != 32 {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}
	tokenHash := sha256.Sum256(tokenBytes)

	// Atomically consume the token (mark used + return in one statement).
	// Prevents TOCTOU race where two concurrent requests both read the token
	// as unused and both proceed to change the password.
	tok, err := srv.store.ConsumePasswordResetToken(ctx, tokenHash[:])
	if err != nil {
		slog.ErrorContext(ctx, "reset-password: consume token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if tok == nil {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
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
		slog.ErrorContext(ctx, "reset-password: hash password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Update the password (also increments token_version, invalidating all sessions).
	if err := srv.store.UpdatePasswordHash(ctx, tok.UserID, newHash, 1); err != nil {
		slog.ErrorContext(ctx, "reset-password: update password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	return &resetPasswordOutput{}, nil
}
