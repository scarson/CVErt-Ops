// ABOUTME: Integration tests for session cookie hygiene between full and pending sign-in sessions.
// ABOUTME: Covers cookie clearing, cross-user token mismatch, typed 401 problems, and has_password.
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// cookieExpired reports whether the response sets the named cookie with a
// past expiry (Max-Age=0), which tells the browser to delete it.
func cookieExpired(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// problemTypeOf decodes an RFC 9457 response body and returns its "type".
func problemTypeOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	var body struct {
		Type string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode problem body: %v", err)
	}
	return body.Type
}

// doSessionRequest sends a JSON request with the CSRF header and the given cookies.
func doSessionRequest(t *testing.T, ctx context.Context, ts *httptest.Server, method, path, body string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req := authedRequest(t, ctx, method, ts.URL+path, body, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704: httptest URL
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// pendingCookie logs in and returns the mfa_pending_token cookie, failing
// the test if the login did not produce a pending session.
func pendingCookie(t *testing.T, ctx context.Context, ts *httptest.Server, email, password string) *http.Cookie {
	t.Helper()
	resp := doLogin(t, ctx, ts, email, password)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	value := cookieValue(resp, "mfa_pending_token")
	if value == "" {
		t.Fatalf("login for %s did not set mfa_pending_token", email)
	}
	return &http.Cookie{Name: "mfa_pending_token", Value: value}
}

// fullSessionCookies logs in a user without pending steps and returns the access token cookie.
func fullSessionCookies(t *testing.T, ctx context.Context, ts *httptest.Server, email, password string) []*http.Cookie {
	t.Helper()
	resp := doLogin(t, ctx, ts, email, password)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	return authedCookies(t, resp)
}

// requireMFAForOrg turns on the org-wide MFA mandate for the given org.
func requireMFAForOrg(t *testing.T, ctx context.Context, db *testutil.TestDB, orgID string) {
	t.Helper()
	id, err := uuid.Parse(orgID)
	if err != nil {
		t.Fatalf("parse org id: %v", err)
	}
	if _, err := db.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", id); err != nil {
		t.Fatalf("set mfa_required_all: %v", err)
	}
}

// ── Cookie hygiene ───────────────────────────────────────────────────────────

func TestPendingLogin_ExpiresAuthCookies(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "pending-clears@example.com", "test-password-1234")
	enrollTOTP(t, ctx, srv, uuid.MustParse(reg.UserID))

	resp := doLogin(t, ctx, ts, "pending-clears@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if !cookieExpired(resp, "access_token") {
		t.Error("pending login must expire any existing access_token cookie")
	}
	if !cookieExpired(resp, "refresh_token") {
		t.Error("pending login must expire any existing refresh_token cookie")
	}
}

func TestFullLogin_ExpiresPendingAndEnrollmentCookies(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "full-clears@example.com", "test-password-1234")

	resp := doLogin(t, ctx, ts, "full-clears@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if cookieValue(resp, "access_token") == "" {
		t.Fatal("full login did not set access_token")
	}
	if !cookieExpired(resp, "mfa_pending_token") {
		t.Error("full login must expire any mfa_pending_token cookie")
	}
	if !cookieExpired(resp, "mfa_enroll_token") {
		t.Error("full login must expire any mfa_enroll_token cookie")
	}
}

func TestMFAVerify_CompletingSignInExpiresEnrollmentCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "verify-clears@example.com", "test-password-1234")
	secret := enrollTOTP(t, ctx, srv, uuid.MustParse(reg.UserID))
	pt := pendingCookie(t, ctx, ts, "verify-clears@example.com", "test-password-1234")

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/verify",
		fmt.Sprintf(`{"method":"totp","code":%q}`, code), []*http.Cookie{pt})
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: got %d, want 200", resp.StatusCode)
	}
	if !cookieExpired(resp, "mfa_pending_token") {
		t.Error("verify must expire mfa_pending_token")
	}
	if !cookieExpired(resp, "mfa_enroll_token") {
		t.Error("verify must expire mfa_enroll_token")
	}
}

func TestLogout_ExpiresPendingAndEnrollmentCookies(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/logout", "", nil)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	for _, name := range []string{"access_token", "refresh_token", "mfa_pending_token", "mfa_enroll_token"} {
		if !cookieExpired(resp, name) {
			t.Errorf("logout must expire %s", name)
		}
	}
}

// ── Cross-user token mismatch ────────────────────────────────────────────────

func TestTOTPSetup_RejectsAccessAndPendingTokensForDifferentUsers(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	// Only the first registrant gets an org, so B registers first to own the mandated org.
	regB := doRegister(t, ctx, ts, "mismatch-b@example.com", "test-password-1234")
	requireMFAForOrg(t, ctx, db, regB.OrgID)
	doRegister(t, ctx, ts, "mismatch-a@example.com", "test-password-1234")

	cookies := fullSessionCookies(t, ctx, ts, "mismatch-a@example.com", "test-password-1234")
	cookies = append(cookies, pendingCookie(t, ctx, ts, "mismatch-b@example.com", "test-password-1234"))

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/setup", "", cookies)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("setup with tokens for two users: got %d, want 401", resp.StatusCode)
	}
}

func TestChangePassword_RejectsAccessAndPendingTokensForDifferentUsers(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "pw-mismatch-a@example.com", "test-password-1234")
	regB := doRegister(t, ctx, ts, "pw-mismatch-b@example.com", "test-password-1234")
	if _, err := db.AdminForcePasswordReset(ctx, uuid.MustParse(regB.UserID)); err != nil {
		t.Fatalf("force reset: %v", err)
	}

	cookies := fullSessionCookies(t, ctx, ts, "pw-mismatch-a@example.com", "test-password-1234")
	cookies = append(cookies, pendingCookie(t, ctx, ts, "pw-mismatch-b@example.com", "test-password-1234"))

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/change-password",
		`{"new_password":"a-brand-new-password"}`, cookies)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("change-password with tokens for two users: got %d, want 401", resp.StatusCode)
	}

	// B's password is unchanged: the old one still opens a pending session.
	loginB := doLogin(t, ctx, ts, "pw-mismatch-b@example.com", "test-password-1234")
	defer loginB.Body.Close() //nolint:errcheck,gosec // G104
	if loginB.StatusCode != http.StatusOK {
		t.Fatalf("B login with original password: got %d, want 200", loginB.StatusCode)
	}
}

// ── Typed 401 problems ───────────────────────────────────────────────────────

func TestMFAVerify_TypedProblems(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "verify-typed@example.com", "test-password-1234")
	enrollTOTP(t, ctx, srv, uuid.MustParse(reg.UserID))
	pt := pendingCookie(t, ctx, ts, "verify-typed@example.com", "test-password-1234")

	tests := []struct {
		name     string
		cookies  []*http.Cookie
		wantType string
	}{
		{"wrong code", []*http.Cookie{pt}, problemTypeInvalidCode},
		{"no pending token", nil, problemTypePendingSessionInvalid},
		{"garbage pending token", []*http.Cookie{{Name: "mfa_pending_token", Value: "not-a-jwt"}}, problemTypePendingSessionInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/verify",
				`{"method":"totp","code":"000000"}`, tc.cookies)
			defer resp.Body.Close() //nolint:errcheck,gosec // G104
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", resp.StatusCode)
			}
			if got := problemTypeOf(t, resp); got != tc.wantType {
				t.Errorf("problem type = %q, want %q", got, tc.wantType)
			}
		})
	}
}

func TestMFAChallenge_InvalidPendingTokenIsTyped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/challenge", `{"method":"totp"}`, nil)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if got := problemTypeOf(t, resp); got != problemTypePendingSessionInvalid {
		t.Errorf("problem type = %q, want %q", got, problemTypePendingSessionInvalid)
	}
}

func TestTOTPConfirm_TypedProblems(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "confirm-typed@example.com", "test-password-1234")
	cookies := fullSessionCookies(t, ctx, ts, "confirm-typed@example.com", "test-password-1234")

	// Without an enrollment cookie the setup step has expired or never ran.
	noEnroll := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`, cookies)
	defer noEnroll.Body.Close() //nolint:errcheck,gosec // G104
	if noEnroll.StatusCode != http.StatusUnauthorized {
		t.Fatalf("confirm without enrollment token: got %d, want 401", noEnroll.StatusCode)
	}
	if got := problemTypeOf(t, noEnroll); got != problemTypeEnrollmentExpired {
		t.Errorf("confirm without enrollment token: type = %q, want %q", got, problemTypeEnrollmentExpired)
	}

	setup := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/setup", "", cookies)
	enrollToken := cookieValue(setup, "mfa_enroll_token")
	setup.Body.Close() //nolint:errcheck,gosec // G104
	if enrollToken == "" {
		t.Fatal("setup did not set mfa_enroll_token")
	}

	withEnroll := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	wrong := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`, withEnroll)
	defer wrong.Body.Close() //nolint:errcheck,gosec // G104
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Fatalf("confirm with wrong code: got %d, want 401", wrong.StatusCode)
	}
	if got := problemTypeOf(t, wrong); got != problemTypeInvalidCode {
		t.Errorf("confirm with wrong code: type = %q, want %q", got, problemTypeInvalidCode)
	}
}

func TestEmailOTPConfirm_WrongCodeIsTyped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "email-typed@example.com", "test-password-1234")
	cookies := fullSessionCookies(t, ctx, ts, "email-typed@example.com", "test-password-1234")

	setup := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/email-otp/setup", "", cookies)
	setup.Body.Close() //nolint:errcheck,gosec // G104
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("email setup: got %d, want 200", setup.StatusCode)
	}

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/email-otp/confirm", `{"code":"000000"}`, cookies)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if got := problemTypeOf(t, resp); got != problemTypeInvalidCode {
		t.Errorf("problem type = %q, want %q", got, problemTypeInvalidCode)
	}
}

func TestEnrollment_PendingTokenProblems(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	garbage := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/setup", "",
		[]*http.Cookie{{Name: "mfa_pending_token", Value: "not-a-jwt"}})
	defer garbage.Body.Close() //nolint:errcheck,gosec // G104
	if garbage.StatusCode != http.StatusUnauthorized {
		t.Fatalf("setup with invalid pending token: got %d, want 401", garbage.StatusCode)
	}
	if got := problemTypeOf(t, garbage); got != problemTypePendingSessionInvalid {
		t.Errorf("setup with invalid pending token: type = %q, want %q", got, problemTypePendingSessionInvalid)
	}

	// With no session cookie at all the request is an ordinary unauthenticated call.
	none := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/setup", "", nil)
	defer none.Body.Close() //nolint:errcheck,gosec // G104
	if none.StatusCode != http.StatusUnauthorized {
		t.Fatalf("setup with no session: got %d, want 401", none.StatusCode)
	}
	if got := problemTypeOf(t, none); got != "" {
		t.Errorf("setup with no session: type = %q, want untyped", got)
	}
}

func TestPasswordReauth_WrongPasswordIsTyped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "reauth-typed@example.com", "test-password-1234")
	cookies := fullSessionCookies(t, ctx, ts, "reauth-typed@example.com", "test-password-1234")
	enrollTOTP(t, ctx, srv, uuid.MustParse(reg.UserID))

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"remove method", http.MethodDelete, "/api/v1/auth/mfa/methods/totp", `{"current_password":"wrong-password-1234"}`},
		{"regenerate codes", http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate", `{"current_password":"wrong-password-1234"}`},
		{"change password", http.MethodPost, "/api/v1/auth/change-password", `{"current_password":"wrong-password-1234","new_password":"a-brand-new-password"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doSessionRequest(t, ctx, ts, tc.method, tc.path, tc.body, cookies)
			defer resp.Body.Close() //nolint:errcheck,gosec // G104
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("got %d, want 401", resp.StatusCode)
			}
			if got := problemTypeOf(t, resp); got != problemTypeInvalidPassword {
				t.Errorf("problem type = %q, want %q", got, problemTypeInvalidPassword)
			}
		})
	}
}

func TestChangePassword_InvalidPendingTokenIsTyped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/change-password",
		`{"new_password":"a-brand-new-password"}`, []*http.Cookie{{Name: "mfa_pending_token", Value: "not-a-jwt"}})
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", resp.StatusCode)
	}
	if got := problemTypeOf(t, resp); got != problemTypePendingSessionInvalid {
		t.Errorf("problem type = %q, want %q", got, problemTypePendingSessionInvalid)
	}
}

// ── Pending token renewal ────────────────────────────────────────────────────

func TestTOTPSetup_RenewsPendingToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "totp-renew@example.com", "test-password-1234")
	requireMFAForOrg(t, ctx, db, reg.OrgID)
	pt := pendingCookie(t, ctx, ts, "totp-renew@example.com", "test-password-1234")

	resp := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/mfa/totp/setup", "", []*http.Cookie{pt})
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("setup: got %d, want 200", resp.StatusCode)
	}
	if cookieValue(resp, "mfa_pending_token") == "" {
		t.Error("restricted TOTP setup must reissue mfa_pending_token with a fresh TTL")
	}
}

// ── /auth/me has_password ───────────────────────────────────────────────────

func TestMe_ReportsWhetherAccountHasPassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "has-password@example.com", "test-password-1234")
	cookies := fullSessionCookies(t, ctx, ts, "has-password@example.com", "test-password-1234")

	readHasPassword := func() bool {
		t.Helper()
		resp := doSessionRequest(t, ctx, ts, http.MethodGet, "/api/v1/auth/me", "", cookies)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("me: got %d, want 200", resp.StatusCode)
		}
		var body struct {
			HasPassword *bool `json:"has_password"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode me: %v", err)
		}
		if body.HasPassword == nil {
			t.Fatal("me response has no has_password field")
		}
		return *body.HasPassword
	}

	if !readHasPassword() {
		t.Error("has_password = false for a password account, want true")
	}

	// OAuth-only accounts have no password hash.
	if _, err := db.Pool().Exec(ctx, "UPDATE users SET password_hash = NULL WHERE id = $1", uuid.MustParse(reg.UserID)); err != nil {
		t.Fatalf("clear password hash: %v", err)
	}
	if readHasPassword() {
		t.Error("has_password = true for an account without a password, want false")
	}
}

// ── Forgot-password reset clears the forced reset ───────────────────────────

func TestResetPassword_ClearsForcePasswordReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "reset-clears-flag@example.com", "test-password-1234")
	userID := uuid.MustParse(reg.UserID)
	if _, err := db.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force reset: %v", err)
	}

	tokenBytes := make([]byte, 32)
	for i := range tokenBytes {
		tokenBytes[i] = byte(i + 7)
	}
	tokenHash := sha256.Sum256(tokenBytes)
	if err := db.CreatePasswordResetToken(ctx, userID, tokenHash[:], time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("CreatePasswordResetToken: %v", err)
	}

	reset := doSessionRequest(t, ctx, ts, http.MethodPost, "/api/v1/auth/reset-password",
		fmt.Sprintf(`{"token":%q,"new_password":"brand-new-password-123"}`, hex.EncodeToString(tokenBytes)), nil)
	reset.Body.Close() //nolint:errcheck,gosec // G104
	if reset.StatusCode != http.StatusOK {
		t.Fatalf("reset: got %d, want 200", reset.StatusCode)
	}

	login := doLogin(t, ctx, ts, "reset-clears-flag@example.com", "brand-new-password-123")
	defer login.Body.Close() //nolint:errcheck,gosec // G104
	body := parseLoginBody(t, login)
	for _, p := range body.Pending {
		if p == "password_reset" {
			t.Fatalf("pending = %v after a completed password reset, want no password_reset", body.Pending)
		}
	}
}
