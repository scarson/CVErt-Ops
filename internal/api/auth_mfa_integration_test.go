// ABOUTME: End-to-end integration tests for complete MFA flows (multi-step scenarios).
// ABOUTME: Exercises register → login → enroll → verify → access as a real user would.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── Full TOTP Login Flow ──────────────────────────────────────────────────────

func TestFullTOTPLoginFlow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	email, password := "full-totp@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register user.
	doRegister(t, ctx, ts, email, password)

	// 2. Login (no MFA) → get tokens.
	loginResp := doLogin(t, ctx, ts, email, password)
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// 3. Enroll TOTP: setup.
	setupReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var setupBody struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(setupResp.Body).Decode(&setupBody); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	enrollToken := cookieValue(setupResp, "mfa_enroll_token")
	setupResp.Body.Close() //nolint:errcheck,gosec

	if setupBody.Secret == "" {
		t.Fatal("setup did not return a secret")
	}
	if enrollToken == "" {
		t.Fatal("setup did not return enrollment token")
	}

	// 3b. Enroll TOTP: confirm.
	code, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	confirmCookies := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	confirmReq := authedRequest(t, ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/totp/confirm",
		fmt.Sprintf(`{"code":%q}`, code), confirmCookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	var confirmOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmOut); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	confirmResp.Body.Close() //nolint:errcheck,gosec

	if len(confirmOut.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(confirmOut.RecoveryCodes))
	}

	// 4. Login again → should get pending token with mfa_challenge.
	loginResp2 := doLogin(t, ctx, ts, email, password)
	body2 := parseLoginBody(t, loginResp2)
	pt := cookieValue(loginResp2, "mfa_pending_token")
	loginResp2.Body.Close() //nolint:errcheck,gosec

	if len(body2.Pending) == 0 || body2.Pending[0] != "mfa_challenge" {
		t.Fatalf("expected pending=[mfa_challenge], got %v", body2.Pending)
	}
	if pt == "" {
		t.Fatal("mfa_pending_token not set on second login")
	}
	if cookieValue(loginResp2, "access_token") != "" {
		t.Error("access_token should NOT be set when MFA is pending")
	}

	// 5. Verify TOTP → get full tokens.
	code2, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code 2: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code2)
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer verifyResp.Body.Close() //nolint:errcheck,gosec

	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify: got %d, want 200", verifyResp.StatusCode)
	}
	accessToken := cookieValue(verifyResp, "access_token")
	if accessToken == "" {
		t.Fatal("access_token not set after MFA verify")
	}

	// 6. Access protected route → 200.
	methodsReq, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/auth/mfa/methods", nil)
	methodsReq.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	methodsResp, err := ts.Client().Do(methodsReq) //nolint:gosec
	if err != nil {
		t.Fatalf("methods request: %v", err)
	}
	defer methodsResp.Body.Close() //nolint:errcheck,gosec

	if methodsResp.StatusCode != http.StatusOK {
		t.Fatalf("protected route: got %d, want 200", methodsResp.StatusCode)
	}
}

// ── Full Email OTP Login Flow ─────────────────────────────────────────────────

func TestFullEmailOTPLoginFlow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "full-emailotp@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register and login (no MFA).
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	loginResp := doLogin(t, ctx, ts, email, password)
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// 2. Enroll email OTP: setup.
	setupReq := authedRequest(t, ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/email-otp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	setupResp.Body.Close() //nolint:errcheck,gosec
	if setupResp.StatusCode != http.StatusOK {
		t.Fatalf("email otp setup: got %d, want 200", setupResp.StatusCode)
	}

	// 2b. Confirm enrollment (inject OTP challenge directly since we can't read email).
	otpCode := "987654"
	codeHash := sha256Hex(otpCode)
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, codeHash, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	confirmReq := authedRequest(t, ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/email-otp/confirm",
		fmt.Sprintf(`{"code":%q}`, otpCode), cookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	var confirmOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmOut); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	confirmResp.Body.Close() //nolint:errcheck,gosec
	if len(confirmOut.RecoveryCodes) != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", len(confirmOut.RecoveryCodes))
	}

	// 3. Login again → pending token.
	loginResp2 := doLogin(t, ctx, ts, email, password)
	body2 := parseLoginBody(t, loginResp2)
	pt := cookieValue(loginResp2, "mfa_pending_token")
	loginResp2.Body.Close() //nolint:errcheck,gosec

	if len(body2.Pending) == 0 || body2.Pending[0] != "mfa_challenge" {
		t.Fatalf("expected pending=[mfa_challenge], got %v", body2.Pending)
	}

	// 4. Create a verification challenge and verify.
	verifyCode := "112233"
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, sha256Hex(verifyCode), time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("create verify challenge: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"email_otp","code":%q}`, verifyCode)
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer verifyResp.Body.Close() //nolint:errcheck,gosec

	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify: got %d, want 200", verifyResp.StatusCode)
	}
	if cookieValue(verifyResp, "access_token") == "" {
		t.Fatal("access_token not set after email OTP verify")
	}
}

// ── Full Recovery Code Flow ───────────────────────────────────────────────────

func TestFullRecoveryCodeFlow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "full-recovery@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register, enroll TOTP, get recovery codes.
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)
	codes, err := srv.store.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}

	// 2. Login → pending token.
	loginResp := doLogin(t, ctx, ts, email, password)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// 3. Verify with recovery code → full tokens.
	verifyBody := fmt.Sprintf(`{"method":"recovery","code":%q}`, codes[0])
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer verifyResp.Body.Close() //nolint:errcheck,gosec

	if verifyResp.StatusCode != http.StatusOK {
		t.Fatalf("verify recovery: got %d, want 200", verifyResp.StatusCode)
	}
	accessToken := cookieValue(verifyResp, "access_token")
	if accessToken == "" {
		t.Fatal("access_token not set after recovery code verify")
	}

	// 4. Check remaining codes decremented.
	methodsReq, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/auth/mfa/methods", nil)
	methodsReq.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	methodsResp, err := ts.Client().Do(methodsReq) //nolint:gosec
	if err != nil {
		t.Fatalf("methods: %v", err)
	}
	defer methodsResp.Body.Close() //nolint:errcheck,gosec

	var methodsBody struct {
		RecoveryCodesRemaining int `json:"recovery_codes_remaining"`
	}
	if err := json.NewDecoder(methodsResp.Body).Decode(&methodsBody); err != nil {
		t.Fatalf("decode methods: %v", err)
	}
	if methodsBody.RecoveryCodesRemaining != 9 {
		t.Errorf("expected 9 remaining codes, got %d", methodsBody.RecoveryCodesRemaining)
	}
}

// ── Full Forced Password Reset with MFA ───────────────────────────────────────

func TestFullForcedPasswordResetWithMFA(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "full-fpr@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register, enroll TOTP.
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// 2. Admin sets force_password_reset.
	if _, err := db.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force password reset: %v", err)
	}

	// 3. Login → pending=["mfa_challenge", "password_reset"].
	loginResp := doLogin(t, ctx, ts, email, password)
	body := parseLoginBody(t, loginResp)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	if len(body.Pending) < 2 {
		t.Fatalf("expected 2+ pending, got %v", body.Pending)
	}
	if body.Pending[0] != "mfa_challenge" || body.Pending[1] != "password_reset" {
		t.Fatalf("expected [mfa_challenge, password_reset], got %v", body.Pending)
	}

	// 4. Verify TOTP → pending=["password_reset"].
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var verifyOut struct {
		Pending []string `json:"pending"`
	}
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyOut); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	verifyResp.Body.Close() //nolint:errcheck,gosec

	if len(verifyOut.Pending) != 1 || verifyOut.Pending[0] != "password_reset" {
		t.Fatalf("after MFA: expected [password_reset], got %v", verifyOut.Pending)
	}
	// Should have reissued pending token (not access token).
	newPT := cookieValue(verifyResp, "mfa_pending_token")
	if newPT == "" {
		t.Fatal("expected new pending token after MFA verify with remaining steps")
	}
	if cookieValue(verifyResp, "access_token") != "" {
		t.Error("access_token should NOT be set with password_reset still pending")
	}

	// 5. Change password using the restricted-mode pending token.
	// The change-password endpoint accepts pending tokens when password_reset is next.
	changePWBody := fmt.Sprintf(`{"current_password":%q,"new_password":"brand-new-pw-5678"}`, password)
	changePWReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/change-password", bytes.NewBufferString(changePWBody))
	changePWReq.Header.Set("Content-Type", "application/json")
	changePWReq.Header.Set("X-Requested-By", "CVErt-Ops")
	changePWReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: newPT})
	changePWResp, err := ts.Client().Do(changePWReq) //nolint:gosec
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	defer changePWResp.Body.Close() //nolint:errcheck,gosec

	if changePWResp.StatusCode != http.StatusOK {
		t.Fatalf("change password: got %d, want 200", changePWResp.StatusCode)
	}

	// Should now have full tokens.
	if cookieValue(changePWResp, "access_token") == "" {
		t.Error("expected access_token after completing password reset")
	}

	// 6. Login with new password should work.
	loginResp3 := doLogin(t, ctx, ts, email, "brand-new-pw-5678")
	body3 := parseLoginBody(t, loginResp3)
	loginResp3.Body.Close() //nolint:errcheck,gosec

	// Should still require MFA (enrolled), but force_password_reset should be cleared.
	if len(body3.Pending) == 0 || body3.Pending[0] != "mfa_challenge" {
		t.Fatalf("expected [mfa_challenge], got %v", body3.Pending)
	}
	// Confirm no password_reset in pending.
	for _, p := range body3.Pending {
		if p == "password_reset" {
			t.Error("password_reset should be cleared after changing password")
		}
	}
}

// ── Full MFA Enrollment Required ──────────────────────────────────────────────

func TestFullMFAEnrollmentRequired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	email, password := "full-mandate@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register user.
	reg := doRegister(t, ctx, ts, email, password)
	orgID, _ := uuid.Parse(reg.OrgID)

	// 2. Enable org-wide MFA mandate.
	if _, err := db.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", orgID); err != nil {
		t.Fatalf("set mfa_required_all: %v", err)
	}

	// 3. Login → pending=["mfa_enrollment_required"].
	loginResp := doLogin(t, ctx, ts, email, password)
	body := parseLoginBody(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	if len(body.Pending) == 0 || body.Pending[0] != "mfa_enrollment_required" {
		t.Fatalf("expected pending=[mfa_enrollment_required], got %v", body.Pending)
	}

	// Login with enrollment mandate issues a pending token with mfa_enrollment_required.
	// Enrollment endpoints accept this pending token via the mfa_pending_token cookie.
	enrollPT := cookieValue(loginResp, "mfa_pending_token")
	if enrollPT == "" {
		t.Fatal("expected mfa_pending_token for enrollment required flow")
	}

	// 4. Enroll TOTP: setup (using pending token, not access token).
	pendingCookies := []*http.Cookie{{Name: "mfa_pending_token", Value: enrollPT}}
	setupReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/totp/setup", nil)
	setupReq.Header.Set("X-Requested-By", "CVErt-Ops")
	for _, c := range pendingCookies {
		setupReq.AddCookie(c)
	}
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	var setupOut struct {
		Secret string `json:"secret"`
	}
	if err := json.NewDecoder(setupResp.Body).Decode(&setupOut); err != nil {
		t.Fatalf("decode setup: %v", err)
	}
	enrollToken := cookieValue(setupResp, "mfa_enroll_token")
	setupResp.Body.Close() //nolint:errcheck,gosec

	if setupOut.Secret == "" || enrollToken == "" {
		t.Fatal("setup did not return secret or enrollment token")
	}

	// 4b. Confirm enrollment.
	code, err := totp.GenerateCode(setupOut.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	confirmCookies := append(pendingCookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	confirmReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/totp/confirm",
		bytes.NewBufferString(fmt.Sprintf(`{"code":%q}`, code)))
	confirmReq.Header.Set("Content-Type", "application/json")
	confirmReq.Header.Set("X-Requested-By", "CVErt-Ops")
	for _, c := range confirmCookies {
		confirmReq.AddCookie(c)
	}
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("confirm: got %d, want 200", confirmResp.StatusCode)
	}

	// 5. Login again — now should get mfa_challenge (enrolled, not enrollment_required).
	loginResp2 := doLogin(t, ctx, ts, email, password)
	body2 := parseLoginBody(t, loginResp2)
	loginResp2.Body.Close() //nolint:errcheck,gosec

	if len(body2.Pending) == 0 {
		t.Fatal("expected pending items after enrollment, got none")
	}
	if body2.Pending[0] != "mfa_challenge" {
		t.Fatalf("expected pending[0]=mfa_challenge (now enrolled), got %v", body2.Pending)
	}
}

// ── Password Reset Does Not Bypass MFA ────────────────────────────────────────

func TestPasswordResetDoesNotBypassMFA(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "reset-mfa@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register, enroll TOTP.
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	// 2. Simulate password reset by changing password hash directly.
	// (A real forgot-password flow ends up changing the hash. Here we change
	// the password via the API using the MFA-authenticated path.)
	loginResp := doLogin(t, ctx, ts, email, password)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Verify MFA to get access.
	code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify",
		bytes.NewBufferString(fmt.Sprintf(`{"method":"totp","code":%q}`, code)))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	cookies := authedCookies(t, verifyResp)
	verifyResp.Body.Close() //nolint:errcheck,gosec

	// Change password.
	changePWReq := authedRequest(t, ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/change-password",
		fmt.Sprintf(`{"current_password":%q,"new_password":"new-pass-after-reset"}`, password),
		cookies)
	changePWResp, err := ts.Client().Do(changePWReq) //nolint:gosec
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	changePWResp.Body.Close() //nolint:errcheck,gosec
	if changePWResp.StatusCode != http.StatusOK {
		t.Fatalf("change password: got %d, want 200", changePWResp.StatusCode)
	}

	// 3. After password change, login → still requires MFA challenge.
	loginResp2 := doLogin(t, ctx, ts, email, "new-pass-after-reset")
	body2 := parseLoginBody(t, loginResp2)
	loginResp2.Body.Close() //nolint:errcheck,gosec

	if len(body2.Pending) == 0 || body2.Pending[0] != "mfa_challenge" {
		t.Fatalf("after password reset: expected [mfa_challenge], got %v", body2.Pending)
	}
	if cookieValue(loginResp2, "access_token") != "" {
		t.Error("access_token should NOT be set — password reset does not bypass MFA")
	}
}

// ── MFA Does Not Apply to API Keys ───────────────────────────────────────────

func TestMFADoesNotApplyToAPIKeys(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "apikey-mfa@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register and enroll MFA.
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	orgID, _ := uuid.Parse(reg.OrgID)
	enrollTOTP(t, ctx, srv, userID)

	// 2. Create an API key directly in the DB.
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate API key: %v", err)
	}
	if _, err := srv.store.CreateAPIKey(ctx, orgID, userID, keyHash, "test-key", "admin", sql.NullTime{}); err != nil {
		t.Fatalf("create API key: %v", err)
	}

	// 3. Make a request with the API key to a chi-authenticated route (not huma).
	// Huma routes use cookie auth; chi routes use RequireAuthenticated() middleware
	// which handles both cookie and Bearer token auth.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+reg.OrgID, nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("api key request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API key org request: got %d, want 200 (MFA should not apply to API keys)", resp.StatusCode)
	}
}

// ── Concurrent Recovery Code Use ──────────────────────────────────────────────

func TestConcurrentRecoveryCodeUse(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "concurrent-rc@example.com", "test-password-1234" //nolint:gosec // G101: test credentials

	// 1. Register, enroll TOTP, get recovery codes.
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)
	codes, err := srv.store.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("generate codes: %v", err)
	}

	// 2. Two goroutines submit the same recovery code simultaneously.
	// We need two separate pending tokens (two login sessions).
	loginResp1 := doLogin(t, ctx, ts, email, password)
	pt1 := cookieValue(loginResp1, "mfa_pending_token")
	loginResp1.Body.Close() //nolint:errcheck,gosec

	loginResp2 := doLogin(t, ctx, ts, email, password)
	pt2 := cookieValue(loginResp2, "mfa_pending_token")
	loginResp2.Body.Close() //nolint:errcheck,gosec

	targetCode := codes[0]
	var successes atomic.Int32
	var wg sync.WaitGroup

	for _, pt := range []string{pt1, pt2} {
		wg.Add(1)
		go func(pendingToken string) {
			defer wg.Done()
			verifyBody := fmt.Sprintf(`{"method":"recovery","code":%q}`, targetCode)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
			resp, err := ts.Client().Do(req) //nolint:gosec
			if err != nil {
				t.Errorf("verify: %v", err)
				return
			}
			resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode == http.StatusOK {
				successes.Add(1)
			}
		}(pt)
	}

	wg.Wait()

	if successes.Load() != 1 {
		t.Errorf("expected exactly 1 successful recovery code use, got %d", successes.Load())
	}
}
