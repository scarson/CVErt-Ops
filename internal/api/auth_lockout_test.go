// ABOUTME: Integration tests for account lockout on repeated failed login attempts.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newLockoutServer creates a Server + httptest.Server with a short lockout duration for tests.
func newLockoutServer(t *testing.T) *httptest.Server {
	t.Helper()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "lockouttest-secret-key",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
		LockoutThreshold:    3, // low threshold for faster tests
		LockoutDuration:     2 * time.Second,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return ts
}

func TestLogin_AccountLockout(t *testing.T) {
	t.Parallel()
	ts := newLockoutServer(t)
	ctx := context.Background()

	doRegister(t, ctx, ts, "lockout@example.com", "test-password-1234")

	// Fail login 3 times (threshold).
	for i := range 3 {
		body := `{"email":"lockout@example.com","password":"wrong-password-wrong"}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("login attempt %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i, resp.StatusCode)
		}
	}

	// 4th attempt with correct password — should be locked out (429).
	body := `{"email":"lockout@example.com","password":"test-password-1234"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("locked attempt: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked: got %d, want 429", resp.StatusCode)
	}

	// Wait for lockout to expire.
	time.Sleep(3 * time.Second)

	// Correct password should now succeed.
	loginResp := doLogin(t, ctx, ts, "lockout@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("after expiry: got %d, want 200", loginResp.StatusCode)
	}
}
