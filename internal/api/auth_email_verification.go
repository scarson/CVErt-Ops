// ABOUTME: HTTP handlers for email verification: verify-email and resend-verification.
// ABOUTME: verify-email is public; resend-verification requires authentication.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/notify"
)

// ── Verify Email ──────────────────────────────────────────────────────────────

// verifyEmailInput is the request body for POST /auth/verify-email.
type verifyEmailInput struct {
	Body struct {
		Token string `json:"token" minLength:"1" doc:"Email verification token (hex-encoded)"`
	}
}

// verifyEmailOutput returns a success message.
type verifyEmailOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

// verifyEmailHandler handles POST /api/v1/auth/verify-email.
func (srv *Server) verifyEmailHandler(ctx context.Context, input *verifyEmailInput) (*verifyEmailOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	// Decode and hash the token.
	tokenBytes, decodeErr := hex.DecodeString(input.Body.Token)
	if decodeErr != nil || len(tokenBytes) != 32 {
		return nil, huma.Error400BadRequest("invalid or expired verification token")
	}
	tokenHash := sha256.Sum256(tokenBytes)

	// Look up the token (filters expired and used tokens).
	tok, err := srv.store.GetEmailVerificationTokenByHash(ctx, tokenHash[:])
	if err != nil {
		slog.ErrorContext(ctx, "verify-email: lookup token", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}
	if tok == nil {
		return nil, huma.Error400BadRequest("invalid or expired verification token")
	}

	// Mark email as verified.
	if err := srv.store.SetEmailVerified(ctx, tok.UserID); err != nil {
		slog.ErrorContext(ctx, "verify-email: set verified", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// Mark token as used.
	if err := srv.store.MarkEmailVerificationTokenUsed(ctx, tok.ID); err != nil {
		slog.ErrorContext(ctx, "verify-email: mark token used", "error", err)
		// Non-fatal — email is already verified.
	}

	return &verifyEmailOutput{Body: struct {
		Message string `json:"message"`
	}{Message: "Email verified successfully."}}, nil
}

// ── Resend Verification ───────────────────────────────────────────────────────

// resendVerificationInput requires authentication via access_token cookie.
type resendVerificationInput struct {
	AccessToken string `cookie:"access_token" doc:"Access token cookie"`
}

// resendVerificationOutput returns a generic message.
type resendVerificationOutput struct {
	Body struct {
		Message string `json:"message"`
	}
}

// resendVerificationHandler handles POST /api/v1/auth/resend-verification.
// Requires authentication. Sends a verification email to the current user.
func (srv *Server) resendVerificationHandler(ctx context.Context, input *resendVerificationInput) (*resendVerificationOutput, error) {
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		return nil, err
	}

	if input.AccessToken == "" {
		return nil, huma.Error401Unauthorized("authentication required")
	}
	claims, err := auth.ParseAccessToken(input.AccessToken, []byte(srv.cfg.JWTSecret))
	if err != nil {
		return nil, huma.Error401Unauthorized("invalid or expired access token")
	}

	user, err := srv.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		slog.ErrorContext(ctx, "resend-verification: lookup user", "error", err)
		return nil, huma.Error500InternalServerError("internal error")
	}

	// If already verified, return success without sending.
	if user.EmailVerified {
		return &resendVerificationOutput{Body: struct {
			Message string `json:"message"`
		}{Message: "Email already verified."}}, nil
	}

	// Generate and send a verification email.
	if err := srv.sendVerificationEmail(ctx, user.ID, user.Email); err != nil {
		slog.ErrorContext(ctx, "resend-verification: send email", "error", err)
		// Non-fatal — return success to avoid leaking internal state.
	}

	return &resendVerificationOutput{Body: struct {
		Message string `json:"message"`
	}{Message: "Verification email sent."}}, nil
}

// sendVerificationEmail generates a token, stores it, and sends a verification email.
// Used by both registration and the resend endpoint.
func (srv *Server) sendVerificationEmail(ctx context.Context, userID uuid.UUID, email string) error {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(srv.cfg.EmailVerificationTokenTTL)

	if err := srv.store.CreateEmailVerificationToken(ctx, userID, tokenHash[:], expiresAt); err != nil {
		return err
	}

	// Build and send verification email.
	verifyURL := srv.cfg.ExternalURL + "/verify-email?token=" + tokenHex
	subject, htmlBody, textBody, renderErr := notify.RenderEmailVerification(notify.EmailVerificationData{
		Email:     email,
		VerifyURL: verifyURL,
		ExpiresIn: formatTTL(srv.cfg.EmailVerificationTokenTTL),
	})
	if renderErr != nil {
		slog.ErrorContext(ctx, "send-verification: render email", "error", renderErr)
		return renderErr
	}

	smtpCfg := notify.SmtpConfig{
		Host:     srv.cfg.SMTPHost,
		Port:     srv.cfg.SMTPPort,
		From:     srv.cfg.SMTPFrom,
		Username: srv.cfg.SMTPUsername,
		Password: srv.cfg.SMTPPassword,
		TLS:      srv.cfg.SMTPTLS,
	}
	if emailErr := notify.EmailSend(ctx, smtpCfg, []string{email}, subject, htmlBody, textBody); emailErr != nil {
		slog.WarnContext(ctx, "send-verification: send email failed", "email", email, "error", emailErr)
		return emailErr
	}

	return nil
}
