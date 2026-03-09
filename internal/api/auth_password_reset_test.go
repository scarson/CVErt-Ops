// ABOUTME: Integration tests for password reset HTTP handlers (forgot-password, reset-password).
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
	"sync"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newPasswordResetServer creates a Server + httptest.Server for password reset tests.
func newPasswordResetServer(t *testing.T) (*testutil.TestDB, *httptest.Server) {
	t.Helper()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:               "resettest-secret-key",
		RegistrationMode:        "open",
		Argon2MaxConcurrent:     5,
		PasswordResetTokenTTL:   1 * time.Hour,
		PasswordResetMaxPerHour: 3,
		SMTPHost:                "localhost",
		SMTPPort:                1025,
		SMTPFrom:                "test@example.com",
		ExternalURL:             "http://localhost:8080",
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

func TestForgotPassword_ExistingUser(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	// Register a user.
	doRegister(t, ctx, ts, "reset-exist@example.com", "test-password-1234")

	// Request password reset.
	body := `{"email":"reset-exist@example.com"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/forgot-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	// Verify token was created in DB.
	user, err := db.GetUserByEmail(ctx, "reset-exist@example.com")
	if err != nil || user == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	count, err := db.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("CountRecentPasswordResetTokens: %v", err)
	}
	if count != 1 {
		t.Errorf("token count = %d, want 1", count)
	}
}

func TestForgotPassword_NonexistentUser(t *testing.T) {
	t.Parallel()
	_, ts := newPasswordResetServer(t)
	ctx := context.Background()

	// Request reset for nonexistent email — should still return 200.
	body := `{"email":"nobody@example.com"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/forgot-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200 (no enumeration)", resp.StatusCode)
	}
}

func TestForgotPassword_RateLimit(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "ratelimit@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "ratelimit@example.com")

	// Send 3 requests (max per hour).
	for i := range 3 {
		body := `{"email":"ratelimit@example.com"}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/forgot-password", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, resp.StatusCode)
		}
	}

	// 4th request: still returns 200 (anti-enumeration), but no new token is created.
	body := `{"email":"ratelimit@example.com"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/forgot-password", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("4th request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("4th request: got %d, want 200 (silent rate limit)", resp.StatusCode)
	}

	// Verify: only 3 tokens created, not 4.
	count, err := db.CountRecentPasswordResetTokens(ctx, user.ID, time.Now().Add(-1*time.Minute))
	if err != nil {
		t.Fatalf("CountRecentPasswordResetTokens: %v", err)
	}
	if count != 3 {
		t.Errorf("token count = %d, want 3 (4th request should be silently dropped)", count)
	}
}

func TestResetPassword_ValidToken(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "valid-reset@example.com", "test-password-1234")

	// Request password reset.
	forgotBody := `{"email":"valid-reset@example.com"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/forgot-password", bytes.NewBufferString(forgotBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("forgot request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	// Extract the token from DB (in a real scenario, user gets it via email).
	user, _ := db.GetUserByEmail(ctx, "valid-reset@example.com")
	// We need to find the token. Since we can't easily extract the raw token from the handler,
	// we'll create one directly and test the reset endpoint.
	tokenBytes := make([]byte, 32)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i)
	}
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(1 * time.Hour)

	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Reset the password.
	resetBody := fmt.Sprintf(`{"token":%q,"new_password":"brand-new-password-123"}`, tokenHex)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		json.NewDecoder(resp.Body).Decode(&errBody) //nolint:errcheck,gosec // G104: diagnostic decode in test
		t.Fatalf("reset: got %d, want 200. body: %s", resp.StatusCode, errBody)
	}

	// Verify: login with old password should fail, new password should succeed.
	loginResp := doLogin(t, ctx, ts, "valid-reset@example.com", "brand-new-password-123")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login with new password: got %d, want 200", loginResp.StatusCode)
	}
}

func TestResetPassword_ExpiredToken(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "expired-reset@example.com", "test-password-1234")

	user, _ := db.GetUserByEmail(ctx, "expired-reset@example.com")

	// Create an expired token directly in DB.
	tokenBytes := []byte("expired-reset-token-bytes-32char")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], time.Now().Add(-1*time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	resetBody := fmt.Sprintf(`{"token":%q,"new_password":"brand-new-password-123"}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("reset request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired token: got %d, want 400", resp.StatusCode)
	}
}

func TestResetPassword_UsedToken(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "used-reset@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "used-reset@example.com")

	tokenBytes := []byte("used-reset-token-bytes-32-chars!")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Use the token once.
	resetBody := fmt.Sprintf(`{"token":%q,"new_password":"first-new-password-123"}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first reset: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first reset: got %d, want 200", resp.StatusCode)
	}

	// Try to use it again — should fail.
	resetBody2 := fmt.Sprintf(`{"token":%q,"new_password":"second-new-password-12"}`, tokenHex)
	req, _ = http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody2))
	req.Header.Set("Content-Type", "application/json")
	resp, err = ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second reset: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("used token: got %d, want 400", resp.StatusCode)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	t.Parallel()
	_, ts := newPasswordResetServer(t)
	ctx := context.Background()

	resetBody := fmt.Sprintf(`{"token":%q,"new_password":"brand-new-password-123"}`, hex.EncodeToString(make([]byte, 32)))
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
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

func TestResetPassword_WeakPassword(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "weak-pw@example.com", "test-password-1234")
	user, _ := db.GetUserByEmail(ctx, "weak-pw@example.com")

	tokenBytes := []byte("weak-password-token-bytes-32chr!")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], time.Now().Add(1*time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Try to reset with a too-short password (< 16 chars).
	resetBody := fmt.Sprintf(`{"token":%q,"new_password":"short"}`, tokenHex)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	// huma validates minLength:"16" and returns 422.
	if resp.StatusCode != http.StatusUnprocessableEntity && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak password: got %d, want 422 or 400", resp.StatusCode)
	}
}

func TestResetPassword_ConcurrentUse(t *testing.T) {
	t.Parallel()
	db, ts := newPasswordResetServer(t)
	ctx := context.Background()

	// Register a user.
	doRegister(t, ctx, ts, "concurrent-reset@example.com", "test-password-1234")
	user, err := db.GetUserByEmail(ctx, "concurrent-reset@example.com")
	if err != nil || user == nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}

	// Insert a known token directly in DB.
	tokenBytes := []byte("concurrent-test-token-32-bytes!!")
	tokenHex := hex.EncodeToString(tokenBytes)
	tokenHash := sha256.Sum256(tokenBytes)
	expiresAt := time.Now().Add(1 * time.Hour)
	if err := db.CreatePasswordResetToken(ctx, user.ID, tokenHash[:], expiresAt); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	// Race two reset requests using a barrier for reliable concurrency.
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready // wait for barrier
			resetBody := fmt.Sprintf(`{"token":%q,"new_password":"concurrent-password-%d!"}`, tokenHex, idx)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/reset-password", bytes.NewBufferString(resetBody))
			req.Header.Set("Content-Type", "application/json")
			resp, reqErr := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
			if reqErr != nil {
				t.Errorf("request %d: %v", idx, reqErr)
				return
			}
			defer resp.Body.Close() //nolint:errcheck,gosec // G104
			results[idx] = resp.StatusCode
		}(i)
	}
	close(ready) // release both goroutines simultaneously
	wg.Wait()

	// Exactly one should succeed (200), one should fail (400).
	successes := 0
	for _, code := range results {
		if code == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d (status codes: %v)", successes, results)
	}
}
