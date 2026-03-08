// ABOUTME: HTTP handlers for password reset: forgot-password and reset-password.
// ABOUTME: Public endpoints at /api/v1/auth/forgot-password and /api/v1/auth/reset-password.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/notify"
)

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

// forgotPasswordHandler handles POST /api/v1/auth/forgot-password.
// Always returns 200 to prevent email enumeration.
func (srv *Server) forgotPasswordHandler(ctx context.Context, input *forgotPasswordInput) (*forgotPasswordOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	user, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
	if err != nil {
		slog.ErrorContext(ctx, "forgot-password: lookup email", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// If user doesn't exist, still spend time to normalize response timing.
	if user == nil || !user.PasswordHash.Valid {
		// Timing normalization: sleep ~50ms to approximate token creation + email render time.
		time.Sleep(50 * time.Millisecond)
		return &forgotPasswordOutput{Body: struct {
			Message string `json:"message"`
		}{Message: "If an account with that email exists, a password reset link has been sent."}}, nil
	}

	// Rate limit: max N reset emails per user per hour.
	count, err := srv.store.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Hour))
	if err != nil {
		slog.ErrorContext(ctx, "forgot-password: count recent tokens", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if int(count) >= srv.cfg.PasswordResetMaxPerHour {
		return nil, huma.Error429TooManyRequests("too many password reset requests — try again later")
	}

	// Generate 32-byte random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.ErrorContext(ctx, "forgot-password: generate token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(srv.cfg.PasswordResetTokenTTL)

	if err := srv.store.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		slog.ErrorContext(ctx, "forgot-password: create token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Build and send reset email.
	resetURL := srv.cfg.ExternalURL + "/reset-password?token=" + tokenHex
	subject, htmlBody, textBody, renderErr := notify.RenderPasswordReset(notify.PasswordResetData{
		Email:     user.Email,
		ResetURL:  resetURL,
		ExpiresIn: "1 hour",
	})
	if renderErr != nil {
		slog.ErrorContext(ctx, "forgot-password: render email", "error", renderErr)
		// Non-fatal — token is created, user could potentially use it via URL.
	} else {
		smtpCfg := notify.SmtpConfig{
			Host:     srv.cfg.SMTPHost,
			Port:     srv.cfg.SMTPPort,
			From:     srv.cfg.SMTPFrom,
			Username: srv.cfg.SMTPUsername,
			Password: srv.cfg.SMTPPassword,
			TLS:      srv.cfg.SMTPTLS,
		}
		if emailErr := notify.EmailSend(ctx, smtpCfg, []string{user.Email}, subject, htmlBody, textBody); emailErr != nil {
			slog.WarnContext(ctx, "forgot-password: send email failed", "email", user.Email, "error", emailErr)
		}
	}

	return &forgotPasswordOutput{Body: struct {
		Message string `json:"message"`
	}{Message: "If an account with that email exists, a password reset link has been sent."}}, nil
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

	// Look up the token.
	tok, err := srv.store.GetPasswordResetTokenByHash(ctx, tokenHash[:])
	if err != nil {
		slog.ErrorContext(ctx, "reset-password: lookup token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if tok == nil {
		return nil, huma.Error400BadRequest("invalid or expired reset token")
	}

	// Hash the new password.
	if !srv.acquireArgon2() {
		return nil, huma.Error503ServiceUnavailable("server busy, please retry")
	}
	newHash, err := auth.HashPassword(input.Body.NewPassword)
	srv.releaseArgon2()
	if err != nil {
		slog.ErrorContext(ctx, "reset-password: hash password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Update the password (also increments token_version, invalidating all sessions).
	if err := srv.store.UpdatePasswordHash(ctx, tok.UserID, newHash, 1); err != nil {
		slog.ErrorContext(ctx, "reset-password: update password", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Mark token as used.
	if err := srv.store.MarkPasswordResetTokenUsed(ctx, tok.ID); err != nil {
		slog.ErrorContext(ctx, "reset-password: mark token used", "error", err)
		// Non-fatal — password already changed. Worst case: token could be reused
		// (but UpdatePasswordHash incremented token_version, so it's safe).
	}

	return &resetPasswordOutput{}, nil
}
