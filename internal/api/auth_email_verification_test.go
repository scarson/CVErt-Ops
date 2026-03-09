// ABOUTME: Integration tests for email verification HTTP handlers (verify-email, resend-verification).
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newEmailVerificationServer creates a Server + httptest.Server for email verification tests.
func newEmailVerificationServer(t *testing.T) (*testutil.TestDB, *httptest.Server) {
	t.Helper()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:                   "verifytest-secret-key",
		RegistrationMode:            "open",
		Argon2MaxConcurrent:         5,
		EmailVerificationTokenTTL:   24 * time.Hour,
		EmailVerificationMaxPerHour: 10,
		SMTPHost:                    "localhost",
		SMTPPort:                    1025,
		SMTPFrom:                    "test@example.com",
		ExternalURL:                 "http://localhost:8080",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return db, ts
}

func TestVerifyEmail_ValidToken(t *testing.T) {
	t.Parallel()
	db, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "verify-valid@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "verify-valid@example.com")

	// Create a verification token directly in DB.
	tokenBytes := make([]byte, 32)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(24 * time.Hour)

	if err := db.CreateEmailVerificationToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	// Verify the email.
	body := fmt.Sprintf(`{"token":%q}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/verify-email", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: got %d, want 200", resp.StatusCode)
	}

	// Verify user is now marked as verified.
	u, err := db.GetUserByID(ctx, user.ID)
	if err != nil || u == nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !u.EmailVerified {
		t.Error("expected email_verified = true after verification")
	}
}

func TestVerifyEmail_ExpiredToken(t *testing.T) {
	t.Parallel()
	db, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "verify-expired@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "verify-expired@example.com")

	tokenBytes := []byte("expired-email-verify-token-32ch!")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreateEmailVerificationToken(ctx, user.ID, tokenHash[:], time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	body := fmt.Sprintf(`{"token":%q}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/verify-email", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired token: got %d, want 400", resp.StatusCode)
	}
}

func TestVerifyEmail_UsedToken(t *testing.T) {
	t.Parallel()
	db, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "verify-used@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "verify-used@example.com")

	tokenBytes := []byte("used-email-verify-token-32chars!")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreateEmailVerificationToken(ctx, user.ID, tokenHash[:], time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("CreateEmailVerificationToken: %v", err)
	}

	// Use the token once.
	body := fmt.Sprintf(`{"token":%q}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/verify-email", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first verify: got %d, want 200", resp.StatusCode)
	}

	// Try to use it again — should fail.
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/verify-email", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("used token: got %d, want 400", resp.StatusCode)
	}
}

func TestVerifyEmail_InvalidToken(t *testing.T) {
	t.Parallel()
	_, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	body := fmt.Sprintf(`{"token":%q}`, hex.EncodeToString(make([]byte, 32)))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/verify-email", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid token: got %d, want 400", resp.StatusCode)
	}
}

func TestResendVerification_Authenticated(t *testing.T) {
	t.Parallel()
	_, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "resend@example.com", "test-password-1234")

	// Login to get auth cookie.
	loginResp := doLogin(t, ctx, ts, "resend@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	accessCookie := cookieValue(loginResp, "access_token")
	if accessCookie == "" {
		t.Fatal("expected access_token cookie")
	}

	// Request verification resend.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	req.Header.Set("Cookie", "access_token="+accessCookie)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resend: got %d, want 200", resp.StatusCode)
	}
}

func TestResendVerification_Unauthenticated(t *testing.T) {
	t.Parallel()
	_, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	// Should require authentication — 401.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: got %d, want 401", resp.StatusCode)
	}
}

func TestResendVerification_InvalidAccessToken(t *testing.T) {
	t.Parallel()
	_, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	// Send with a garbage access_token cookie — should get 401.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	req.Header.Set("Cookie", "access_token=not-a-valid-jwt")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token: got %d, want 401", resp.StatusCode)
	}
}

func TestResendVerification_RateLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Set EmailVerificationMaxPerHour = 4 so that registration (1 token) + 3 resends = 4
	// hits the limit on the 4th resend attempt.
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:                   "verifytest-secret-key",
		RegistrationMode:            "open",
		Argon2MaxConcurrent:         5,
		EmailVerificationTokenTTL:   24 * time.Hour,
		EmailVerificationMaxPerHour: 4,
		SMTPHost:                    "localhost",
		SMTPPort:                    1025,
		SMTPFrom:                    "test@example.com",
		ExternalURL:                 "http://localhost:8080",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	// Registration creates 1 implicit token.
	doRegister(t, ctx, ts, "resend-ratelimit@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "resend-ratelimit@example.com")

	loginResp := doLogin(t, ctx, ts, "resend-ratelimit@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	accessCookie := cookieValue(loginResp, "access_token")
	if accessCookie == "" {
		t.Fatal("expected access_token cookie")
	}

	// 3 resends should succeed (total tokens: 1 registration + 3 resends = 4 = limit).
	for i := range 3 {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
		req.Header.Set("Cookie", "access_token="+accessCookie)
		req.Header.Set("X-Requested-By", "CVErt-Ops")
		resp, reqErr := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
		if reqErr != nil {
			t.Fatalf("resend %d: %v", i, reqErr)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("resend %d: got %d, want 200", i, resp.StatusCode)
		}
	}

	// 4th resend should be rate-limited (429).
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	req.Header.Set("Cookie", "access_token="+accessCookie)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("4th resend: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("4th resend: got %d, want 429", resp.StatusCode)
	}

	// Verify: only 4 tokens in DB (1 from registration + 3 resends).
	count, err := db.CountRecentEmailVerificationTokens(ctx, user.ID, time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("CountRecentEmailVerificationTokens: %v", err)
	}
	if count != 4 {
		t.Errorf("token count = %d, want 4", count)
	}
}

func TestResendVerification_SMTPFailure(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Use an invalid SMTP port to force email sending to fail.
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:                   "verifytest-secret-key",
		RegistrationMode:            "open",
		Argon2MaxConcurrent:         5,
		EmailVerificationTokenTTL:   24 * time.Hour,
		EmailVerificationMaxPerHour: 10,
		SMTPHost:                    "localhost",
		SMTPPort:                    19999,
		SMTPFrom:                    "test@example.com",
		ExternalURL:                 "http://localhost:8080",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	// Registration will fail to send verification email (bad SMTP), but user is created.
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, "smtp-fail@example.com", "test-password-1234")
	regReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	regReq.Header.Set("Content-Type", "application/json")
	regResp, err := ts.Client().Do(regReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	regResp.Body.Close() //nolint:errcheck,gosec

	// Mark email unverified (registration may have created it but not verified).
	user, _ := db.GetUserByEmail(ctx, "smtp-fail@example.com")
	if user == nil {
		t.Fatal("user not created despite SMTP failure")
	}

	loginResp := doLogin(t, ctx, ts, "smtp-fail@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	accessCookie := cookieValue(loginResp, "access_token")
	if accessCookie == "" {
		t.Fatal("expected access_token cookie")
	}

	// Resend should fail because SMTP is unreachable.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	req.Header.Set("Cookie", "access_token="+accessCookie)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	// Should NOT return 200 with "Verification email sent." when email failed.
	if resp.StatusCode == http.StatusOK {
		var respBody struct {
			Message string `json:"message"`
		}
		json.NewDecoder(resp.Body).Decode(&respBody) //nolint:errcheck,gosec // G104: diagnostic decode in test
		if respBody.Message == "Verification email sent." {
			t.Fatal("resend claims email sent on SMTP failure — should report error")
		}
	}
	// Accept 500 as valid — the important thing is it doesn't falsely claim success.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("SMTP failure: got %d, want 500", resp.StatusCode)
	}
}

func TestResendVerification_AlreadyVerified(t *testing.T) {
	t.Parallel()
	db, ts := newEmailVerificationServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "already-verified@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "already-verified@example.com")

	// Mark as verified.
	if err := db.SetEmailVerified(ctx, user.ID); err != nil {
		t.Fatalf("SetEmailVerified: %v", err)
	}

	// Login.
	loginResp := doLogin(t, ctx, ts, "already-verified@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	accessCookie := cookieValue(loginResp, "access_token")

	// Request resend — should return 200 but not actually send (no error).
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/resend-verification", nil)
	req.Header.Set("Cookie", "access_token="+accessCookie)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("already verified: got %d, want 200", resp.StatusCode)
	}
}
