// ABOUTME: Integration tests for account lockout on repeated failed MFA verification.
// ABOUTME: Covers verify refusal while locked and lockout persistence across password re-login.
package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// mfaLockoutThreshold is the lockout threshold used by these tests. It is low
// so each test stays under the per-IP auth rate limit burst.
const mfaLockoutThreshold = 3

// newMFALockoutServer creates an MFA test server whose lockout threshold is
// mfaLockoutThreshold and whose lockout lasts longer than any test.
func newMFALockoutServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	srv, ts := newMFAServer(t, db)
	srv.lockout = newLockoutManager(db.Store, mfaLockoutThreshold, time.Hour)
	return srv, ts
}

// loginForPendingToken logs in with a password and returns the MFA pending token.
func loginForPendingToken(t *testing.T, ctx context.Context, ts *httptest.Server, email, password string) string {
	t.Helper()
	resp := doLogin(t, ctx, ts, email, password)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}
	token := cookieValue(resp, "mfa_pending_token")
	if token == "" {
		t.Fatal("login did not set mfa_pending_token")
	}
	return token
}

// postMFAVerify submits a code to /auth/mfa/verify and returns the status and body.
func postMFAVerify(t *testing.T, ctx context.Context, ts *httptest.Server, pendingToken, method, code string) (int, string) {
	t.Helper()
	body := fmt.Sprintf(`{"method":%q,"code":%q}`, method, code)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(requestCookie("mfa_pending_token", pendingToken))
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read verify body: %v", err)
	}
	return resp.StatusCode, string(respBody)
}

// assertAccountLocked fails the test unless the response is the account
// lockout refusal (not the per-IP rate limit, which also returns 429).
func assertAccountLocked(t *testing.T, status int, body string) {
	t.Helper()
	if status != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429 (account locked); body: %s", status, body)
	}
	if !strings.Contains(body, "account temporarily locked") {
		t.Fatalf("429 is not the account lockout response; body: %s", body)
	}
}

func TestMFAVerify_RefusesWhileAccountLocked(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFALockoutServer(t, db)

	const email, password = "mfa-lock@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	pendingToken := loginForPendingToken(t, ctx, ts, email, password)

	for i := range mfaLockoutThreshold {
		status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", "000000")
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401; body: %s", i, status, body)
		}
	}

	// The account is now locked: even a valid code must be refused.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", code)
	assertAccountLocked(t, status, body)
}

func TestMFAVerify_WrongLengthCodesCountTowardLockout(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFALockoutServer(t, db)

	const email, password = "mfa-length@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	pendingToken := loginForPendingToken(t, ctx, ts, email, password)

	wrongLengthCodes := []string{"12345", "1234567", "12345 "}
	if len(wrongLengthCodes) != mfaLockoutThreshold {
		t.Fatalf("got %d codes, want one per failure up to the threshold %d", len(wrongLengthCodes), mfaLockoutThreshold)
	}
	for _, wrongCode := range wrongLengthCodes {
		status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", wrongCode)
		if status != http.StatusUnauthorized {
			t.Fatalf("code %q: got %d, want 401; body: %s", wrongCode, status, body)
		}
	}

	// Each wrong-length code counted, so even a valid code is refused.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", code)
	assertAccountLocked(t, status, body)
}

func TestMFAVerify_PasswordReloginDoesNotResetFailures(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFALockoutServer(t, db)

	const email, password = "mfa-relogin@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// Guess one code fewer than the threshold, then log in again with the
	// password before the account locks.
	pendingToken := loginForPendingToken(t, ctx, ts, email, password)
	for i := range mfaLockoutThreshold - 1 {
		status, body := postMFAVerify(t, ctx, ts, pendingToken, "recovery", "wrong-recovery-code")
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401; body: %s", i, status, body)
		}
	}

	pendingToken = loginForPendingToken(t, ctx, ts, email, password)
	status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", "000000")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong code after re-login: got %d, want 401; body: %s", status, body)
	}

	// The password login must not have cleared the earlier MFA failures, so
	// the account is locked and a valid code is refused.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	status, body = postMFAVerify(t, ctx, ts, pendingToken, "totp", code)
	assertAccountLocked(t, status, body)
}

func TestMFAVerify_SuccessResetsFailures(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFALockoutServer(t, db)

	const email, password = "mfa-reset@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	pendingToken := loginForPendingToken(t, ctx, ts, email, password)
	for i := range mfaLockoutThreshold - 1 {
		status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", "000000")
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401; body: %s", i, status, body)
		}
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	if status, body := postMFAVerify(t, ctx, ts, pendingToken, "totp", code); status != http.StatusOK {
		t.Fatalf("valid code: got %d, want 200; body: %s", status, body)
	}

	state, err := db.GetLoginLockoutState(ctx, email)
	if err != nil {
		t.Fatalf("GetLoginLockoutState: %v", err)
	}
	if state.FailedCount != 0 || state.LockedAt != nil {
		t.Errorf("after MFA success: failed_login_count=%d locked_at=%v, want 0 and nil",
			state.FailedCount, state.LockedAt)
	}
}
