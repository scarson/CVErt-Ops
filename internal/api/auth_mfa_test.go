// ABOUTME: Integration tests for MFA challenge, verify, and login flow handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newMFAServer creates a server with MFA config and an SSO encryption key.
func newMFAServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:               "mfa-test-secret-at-least-32-bytes",
		RegistrationMode:        "open",
		Argon2MaxConcurrent:     5,
		MFAEmailOTPTTL:          10 * time.Minute,
		MFAEmailOTPMaxPerHour:   5,
		MFAChallengeMaxAttempts: 3,
		MFAPendingTokenTTL:      5 * time.Minute,
		SSOEncryptionKey:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex chars = 32 bytes
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return srv, ts
}

// enrollTOTP creates a TOTP credential directly in the database for testing.
// Returns the plaintext TOTP secret for code generation.
func enrollTOTP(t *testing.T, ctx context.Context, srv *Server, userID uuid.UUID) string {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXP" //nolint:gosec // G101: test TOTP secret
	encKey, err := srv.ssoEncryptionKey()
	if err != nil {
		t.Fatalf("enrollTOTP: encryption key: %v", err)
	}
	secretEnc, err := crypto.Encrypt(encKey, []byte(secret))
	if err != nil {
		t.Fatalf("enrollTOTP: encrypt: %v", err)
	}
	if _, err := srv.store.CreateMFACredential(ctx, userID, "totp", secretEnc); err != nil {
		t.Fatalf("enrollTOTP: create credential: %v", err)
	}
	return secret
}

// enrollEmailOTP creates an email OTP credential directly in the database.
func enrollEmailOTP(t *testing.T, ctx context.Context, srv *Server, userID uuid.UUID) {
	t.Helper()
	if _, err := srv.store.CreateMFACredential(ctx, userID, "email_otp", nil); err != nil {
		t.Fatalf("enrollEmailOTP: create credential: %v", err)
	}
}

// loginBody is the response body shape for login.
type loginBody struct {
	UserID  string   `json:"user_id"`
	Pending []string `json:"pending"`
	Methods []string `json:"methods"`
}

// parseLoginBody reads and parses the login response body.
func parseLoginBody(t *testing.T, resp *http.Response) loginBody {
	t.Helper()
	var body loginBody
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode login body: %v", err)
	}
	return body
}

// ── Login with MFA tests ────────────────────────────────────────────────────

func TestLoginNoMFA_NoMandate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "nomfa@example.com", "test-password-1234")
	resp := doLogin(t, ctx, ts, "nomfa@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec,gosec

	body := parseLoginBody(t, resp)
	if len(body.Pending) != 0 {
		t.Errorf("expected no pending items, got %v", body.Pending)
	}
	if cookieValue(resp, "access_token") == "" {
		t.Error("access_token cookie not set")
	}
	if cookieValue(resp, "refresh_token") == "" {
		t.Error("refresh_token cookie not set")
	}
}

func TestLoginWithMFAEnrolled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "mfauser@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	resp := doLogin(t, ctx, ts, "mfauser@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}

	body := parseLoginBody(t, resp)
	if len(body.Pending) == 0 || body.Pending[0] != "mfa_challenge" {
		t.Errorf("expected pending=[mfa_challenge], got %v", body.Pending)
	}
	if len(body.Methods) == 0 || body.Methods[0] != "totp" {
		t.Errorf("expected methods=[totp], got %v", body.Methods)
	}
	if cookieValue(resp, "mfa_pending_token") == "" {
		t.Error("mfa_pending_token cookie not set")
	}
	if cookieValue(resp, "access_token") != "" {
		t.Error("access_token should NOT be set when MFA is pending")
	}
}

func TestLoginNoMFA_MFARequired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "mandated@example.com", "test-password-1234")
	orgID, _ := uuid.Parse(reg.OrgID)

	// Set org-level mfa_required_all via raw SQL (no store method needed for test setup).
	if _, err := db.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", orgID); err != nil {
		t.Fatalf("set mfa_required_all: %v", err)
	}

	resp := doLogin(t, ctx, ts, "mandated@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec,gosec

	body := parseLoginBody(t, resp)
	if len(body.Pending) == 0 || body.Pending[0] != "mfa_enrollment_required" {
		t.Errorf("expected pending=[mfa_enrollment_required], got %v", body.Pending)
	}
}

func TestLoginMFA_ForcePasswordReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "forcereset@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	// Set force_password_reset.
	if _, err := db.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force password reset: %v", err)
	}

	resp := doLogin(t, ctx, ts, "forcereset@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec,gosec

	body := parseLoginBody(t, resp)
	// Should have both mfa_challenge and password_reset.
	if len(body.Pending) < 2 {
		t.Fatalf("expected at least 2 pending items, got %v", body.Pending)
	}
	if body.Pending[0] != "mfa_challenge" {
		t.Errorf("expected pending[0]=mfa_challenge, got %s", body.Pending[0])
	}
	if body.Pending[1] != "password_reset" {
		t.Errorf("expected pending[1]=password_reset, got %s", body.Pending[1])
	}
}

// ── MFA Challenge tests ────────────────────────────────────────────────────

func TestMFAChallengeEmailOTP(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "emailotp@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollEmailOTP(t, ctx, srv, userID)

	// Login to get pending token.
	loginResp := doLogin(t, ctx, ts, "emailotp@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Request email OTP challenge.
	reqBody := `{"method":"email_otp"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/challenge", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge: got %d, want 200", resp.StatusCode)
	}
}

func TestMFAChallengeTOTP(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "totpchallenge@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, "totpchallenge@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	reqBody := `{"method":"totp"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/challenge", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp challenge: got %d, want 200", resp.StatusCode)
	}
}

func TestMFAChallengeInvalidToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	reqBody := `{"method":"totp"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/challenge", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: "invalid-token"})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token challenge: got %d, want 401", resp.StatusCode)
	}
}

// ── MFA Verify tests ────────────────────────────────────────────────────────

func TestMFAVerifyTOTP(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "verifytotp@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// Login to get pending token.
	loginResp := doLogin(t, ctx, ts, "verifytotp@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Generate valid TOTP code.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	// Verify.
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify TOTP: got %d, want 200", resp.StatusCode)
	}

	// Should have access_token and empty pending.
	var body struct {
		Pending []string `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	if len(body.Pending) != 0 {
		t.Errorf("expected empty pending, got %v", body.Pending)
	}
	if cookieValue(resp, "access_token") == "" {
		t.Error("access_token cookie not set after MFA verify")
	}
}

func TestMFAVerifyEmailOTP(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "verifyemail@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollEmailOTP(t, ctx, srv, userID)

	// Login to get pending token.
	loginResp := doLogin(t, ctx, ts, "verifyemail@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Create an email OTP challenge directly (simulating challenge endpoint).
	code := "123456"
	codeHash := sha256Hex(code)
	expiresAt := time.Now().Add(10 * time.Minute)
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, codeHash, expiresAt); err != nil {
		t.Fatalf("create email OTP challenge: %v", err)
	}

	// Verify.
	verifyBody := fmt.Sprintf(`{"method":"email_otp","code":%q}`, code)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify email OTP: got %d, want 200", resp.StatusCode)
	}
	if cookieValue(resp, "access_token") == "" {
		t.Error("access_token cookie not set after email OTP verify")
	}
}

func TestMFAVerifyRecoveryCode(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "verifyrecovery@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	// Generate recovery codes.
	codes, err := srv.store.GenerateRecoveryCodes(ctx, userID)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}

	// Login to get pending token.
	loginResp := doLogin(t, ctx, ts, "verifyrecovery@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Verify with a recovery code.
	verifyBody := fmt.Sprintf(`{"method":"recovery","code":%q}`, codes[0])
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify recovery: got %d, want 200", resp.StatusCode)
	}
	if cookieValue(resp, "access_token") == "" {
		t.Error("access_token cookie not set after recovery code verify")
	}
}

func TestMFAVerifyWrongCode(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "wrongcode@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, "wrongcode@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Submit wrong code.
	verifyBody := `{"method":"totp","code":"000000"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: got %d, want 401", resp.StatusCode)
	}
}

func TestMFAVerifyTOTPReplay(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "replay@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}

	// First verify — should succeed.
	loginResp1 := doLogin(t, ctx, ts, "replay@example.com", "test-password-1234")
	pt1 := cookieValue(loginResp1, "mfa_pending_token")
	loginResp1.Body.Close() //nolint:errcheck,gosec

	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req1.Header.Set("Content-Type", "application/json")
	req1.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt1})
	resp1, err := ts.Client().Do(req1) //nolint:gosec
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	resp1.Body.Close() //nolint:errcheck,gosec
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first verify: got %d, want 200", resp1.StatusCode)
	}

	// Second verify with same code — should fail (replay).
	loginResp2 := doLogin(t, ctx, ts, "replay@example.com", "test-password-1234")
	pt2 := cookieValue(loginResp2, "mfa_pending_token")
	loginResp2.Body.Close() //nolint:errcheck,gosec

	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt2})
	resp2, err := ts.Client().Do(req2) //nolint:gosec
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay: got %d, want 401", resp2.StatusCode)
	}
}

func TestMFAVerifyTokenVersionMismatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "tvmismatch@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, "tvmismatch@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Increment token_version (simulating admin action).
	if _, err := srv.store.IncrementTokenVersion(ctx, userID); err != nil {
		t.Fatalf("increment token version: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}

	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("tv mismatch: got %d, want 401", resp.StatusCode)
	}
}

func TestMFAVerifyWithRemainingPending(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "remaining@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// Set force_password_reset so pending has two items.
	if _, err := db.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force password reset: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "remaining@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}

	// Verify MFA — should leave password_reset pending.
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("verify request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify remaining: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Pending []string `json:"pending"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Pending) != 1 || body.Pending[0] != "password_reset" {
		t.Errorf("expected pending=[password_reset], got %v", body.Pending)
	}
	// Should NOT have access_token yet.
	if cookieValue(resp, "access_token") != "" {
		t.Error("access_token should NOT be set when password_reset is still pending")
	}
}

// ── TOTP Enrollment tests ─────────────────────────────────────────────────

// authedCookies returns an access_token cookie from a login response (no MFA).
func authedCookies(t *testing.T, resp *http.Response) []*http.Cookie {
	t.Helper()
	for _, c := range resp.Cookies() {
		if c.Name == "access_token" {
			return []*http.Cookie{c}
		}
	}
	t.Fatal("no access_token cookie in login response")
	return nil
}

// authedRequest creates an HTTP request with access token cookies and the
// X-Requested-By CSRF header (required for state-changing cookie-authed requests).
func authedRequest(t *testing.T, ctx context.Context, method, url string, body string, cookies []*http.Cookie) *http.Request {
	t.Helper()
	var req *http.Request
	if body != "" {
		req, _ = http.NewRequestWithContext(ctx, method, url, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequestWithContext(ctx, method, url, nil)
	}
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return req
}

func TestTOTPSetup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "totp-setup@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "totp-setup@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("totp setup: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		QRCodeURI string `json:"qr_code_uri"`
		Secret    string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode setup response: %v", err)
	}
	if body.QRCodeURI == "" {
		t.Error("qr_code_uri is empty")
	}
	if body.Secret == "" {
		t.Error("secret is empty")
	}
	if cookieValue(resp, "mfa_enroll_token") == "" {
		t.Error("mfa_enroll_token cookie not set")
	}
}

func TestTOTPConfirm(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "totp-confirm@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "totp-confirm@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Call setup to get enrollment token.
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

	// Generate valid TOTP code.
	code, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}

	// Confirm enrollment.
	confirmBody := fmt.Sprintf(`{"code":%q}`, code)
	confirmCookies := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	confirmReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/confirm", confirmBody, confirmCookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("totp confirm: got %d, want 200", confirmResp.StatusCode)
	}

	var confirmOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmOut); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	if len(confirmOut.RecoveryCodes) != 10 {
		t.Errorf("expected 10 recovery codes, got %d", len(confirmOut.RecoveryCodes))
	}
}

func TestTOTPConfirmWrongCode(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "totp-wrong@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "totp-wrong@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Call setup.
	setupReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	enrollToken := cookieValue(setupResp, "mfa_enroll_token")
	setupResp.Body.Close() //nolint:errcheck,gosec

	// Confirm with wrong code.
	confirmCookies := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	confirmReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/confirm", `{"code":"000000"}`, confirmCookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong code: got %d, want 401", confirmResp.StatusCode)
	}
}

func TestTOTPConfirmWithoutSetup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "totp-nosetup@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "totp-nosetup@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Confirm without enrollment cookie.
	confirmReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/confirm", `{"code":"123456"}`, cookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no setup: got %d, want 401", confirmResp.StatusCode)
	}
}

func TestTOTPDoubleEnrollment(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "totp-double@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollTOTP(t, ctx, srv, userID) // Already enrolled.

	loginResp := doLogin(t, ctx, ts, "totp-double@example.com", "test-password-1234")
	// This user has MFA, so login returns pending token. We need access token instead.
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Use a fresh login without MFA to get access token — actually, can't.
	// The user has MFA so they get a pending token. For this test, we can
	// do the full MFA verify flow to get the access token.
	pt := cookieValue(loginResp, "mfa_pending_token")
	code, err := totp.GenerateCode("JBSWY3DPEHPK3PXP", time.Now())
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
	cookies := authedCookies(t, verifyResp)
	verifyResp.Body.Close() //nolint:errcheck,gosec

	// Now try to set up TOTP again — should get 409.
	setupReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer setupResp.Body.Close() //nolint:errcheck,gosec

	if setupResp.StatusCode != http.StatusConflict {
		t.Fatalf("double enrollment: got %d, want 409", setupResp.StatusCode)
	}
}

func TestTOTPConfirmDecryptsWithPreviousKey(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Use the standard old key for setup.
	oldKeyHex := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars = 32 bytes
	srv, ts := newMFAServer(t, db)                                                  // uses oldKeyHex as SSOEncryptionKey

	doRegister(t, ctx, ts, "totp-rotate@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "totp-rotate@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Call setup — enrollment token's SecretEnc is encrypted with oldKey.
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

	// Rotate keys: new current key, previous = old key.
	newKeyHex := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	srv.cfg.SSOEncryptionKey = newKeyHex
	srv.cfg.SSOEncryptionKeyPrevious = oldKeyHex

	// Generate valid TOTP code from the plaintext secret.
	code, err := totp.GenerateCode(setupBody.Secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}

	// Confirm enrollment — must decrypt with fallback to previous key.
	confirmBody := fmt.Sprintf(`{"code":%q}`, code)
	confirmCookies := append(cookies, &http.Cookie{Name: "mfa_enroll_token", Value: enrollToken})
	confirmReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/confirm", confirmBody, confirmCookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusOK {
		body, _ := json.Marshal(confirmResp.Status)
		t.Fatalf("totp confirm after key rotation: got %d (%s), want 200", confirmResp.StatusCode, string(body))
	}

	var confirmOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmOut); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	if len(confirmOut.RecoveryCodes) != 10 {
		t.Errorf("expected 10 recovery codes, got %d", len(confirmOut.RecoveryCodes))
	}
}

// ── Email OTP Enrollment tests ────────────────────────────────────────────

func TestEmailOTPSetup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "email-setup@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "email-setup@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/email-otp/setup", "", cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("email otp setup: got %d, want 200", resp.StatusCode)
	}
}

func TestEmailOTPConfirm(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "email-confirm@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	loginResp := doLogin(t, ctx, ts, "email-confirm@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Call setup (this creates an OTP challenge in DB).
	setupReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/email-otp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	setupResp.Body.Close() //nolint:errcheck,gosec

	// Look up the challenge hash from DB to get the code.
	// Since we can't easily extract the code, create one directly.
	code := "654321"
	codeHash := sha256Hex(code)
	expiresAt := time.Now().Add(10 * time.Minute)
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, codeHash, expiresAt); err != nil {
		t.Fatalf("create challenge: %v", err)
	}

	// Confirm.
	confirmBody := fmt.Sprintf(`{"code":%q}`, code)
	confirmReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/email-otp/confirm", confirmBody, cookies)
	confirmResp, err := ts.Client().Do(confirmReq) //nolint:gosec
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	defer confirmResp.Body.Close() //nolint:errcheck,gosec

	if confirmResp.StatusCode != http.StatusOK {
		t.Fatalf("email otp confirm: got %d, want 200", confirmResp.StatusCode)
	}

	var confirmOut struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(confirmResp.Body).Decode(&confirmOut); err != nil {
		t.Fatalf("decode confirm: %v", err)
	}
	if len(confirmOut.RecoveryCodes) != 10 {
		t.Errorf("expected 10 recovery codes, got %d", len(confirmOut.RecoveryCodes))
	}
}

func TestEmailOTPAlreadyEnrolled(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "email-dup@example.com", "test-password-1234")
	userID, _ := uuid.Parse(reg.UserID)
	enrollEmailOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, "email-dup@example.com", "test-password-1234")
	// This user has MFA enrolled, so login gives pending token.
	// Verify to get access token.
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	// Create a challenge and verify email OTP to get access token.
	otpCode := "111222"
	codeHash := sha256Hex(otpCode)
	if err := srv.store.CreateEmailOTPChallenge(ctx, userID, codeHash, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"email_otp","code":%q}`, otpCode)
	verifyReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt})
	verifyResp, err := ts.Client().Do(verifyReq) //nolint:gosec
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	cookies := authedCookies(t, verifyResp)
	verifyResp.Body.Close() //nolint:errcheck,gosec

	// Try to set up email OTP again — should get 409.
	setupReq := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/email-otp/setup", "", cookies)
	setupResp, err := ts.Client().Do(setupReq) //nolint:gosec
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	defer setupResp.Body.Close() //nolint:errcheck,gosec

	if setupResp.StatusCode != http.StatusConflict {
		t.Fatalf("already enrolled: got %d, want 409", setupResp.StatusCode)
	}
}

// ── MFA Management tests ─────────────────────────────────────────────────

// fullTOTPLogin does register → login → MFA verify → returns access token cookies.
func fullTOTPLogin(t *testing.T, ctx context.Context, srv *Server, ts *httptest.Server, email, password string) (uuid.UUID, []*http.Cookie) {
	t.Helper()
	reg := doRegister(t, ctx, ts, email, password)
	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, email, password)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

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
	cookies := authedCookies(t, verifyResp)
	verifyResp.Body.Close() //nolint:errcheck,gosec
	return userID, cookies
}

func TestMFAMethodsList(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	_, cookies := fullTOTPLogin(t, ctx, srv, ts, "methods-list@example.com", "test-password-1234")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/auth/mfa/methods", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("methods list: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("methods list: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Methods                []struct{ Method string } `json:"methods"`
		RecoveryCodesRemaining int                       `json:"recovery_codes_remaining"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Methods) != 1 || body.Methods[0].Method != "totp" {
		t.Errorf("expected [totp], got %v", body.Methods)
	}
}

func TestMFAMethodsListEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "methods-empty@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "methods-empty@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/auth/mfa/methods", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("methods list: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("methods list: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Methods  []struct{ Method string } `json:"methods"`
		Required bool                      `json:"required"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Methods) != 0 {
		t.Errorf("expected empty methods, got %v", body.Methods)
	}
	if body.Required {
		t.Error("expected required=false")
	}
}

func TestMFARemoveMethod(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	userID, cookies := fullTOTPLogin(t, ctx, srv, ts, "mfa-remove@example.com", "test-password-1234")
	// Also enroll email OTP so TOTP isn't the last method.
	enrollEmailOTP(t, ctx, srv, userID)

	// Remove TOTP.
	req := authedRequest(t, ctx, http.MethodDelete, ts.URL+"/api/v1/auth/mfa/methods/totp", `{"current_password":"test-password-1234"}`, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("remove TOTP: got %d, want 204", resp.StatusCode)
	}
}

func TestMFARemoveLastMethodBlocked(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "remove-blocked@example.com", "test-password-1234")
	orgID, _ := uuid.Parse(reg.OrgID)
	// Set org-level MFA mandate.
	if _, err := db.Pool().Exec(ctx, "UPDATE organizations SET mfa_required_all = true WHERE id = $1", orgID); err != nil {
		t.Fatalf("set mfa_required_all: %v", err)
	}

	userID, _ := uuid.Parse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	loginResp := doLogin(t, ctx, ts, "remove-blocked@example.com", "test-password-1234")
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

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
	cookies := authedCookies(t, verifyResp)
	verifyResp.Body.Close() //nolint:errcheck,gosec

	// Try to remove the last (only) method — should be blocked.
	removeReq := authedRequest(t, ctx, http.MethodDelete, ts.URL+"/api/v1/auth/mfa/methods/totp", `{"current_password":"test-password-1234"}`, cookies)
	removeResp, err := ts.Client().Do(removeReq) //nolint:gosec
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	defer removeResp.Body.Close() //nolint:errcheck,gosec

	if removeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("remove last method (mandated): got %d, want 403", removeResp.StatusCode)
	}
}

func TestMFARemoveWrongPassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	_, cookies := fullTOTPLogin(t, ctx, srv, ts, "remove-wrong-pw@example.com", "test-password-1234")

	req := authedRequest(t, ctx, http.MethodDelete, ts.URL+"/api/v1/auth/mfa/methods/totp", `{"current_password":"wrong-password"}`, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", resp.StatusCode)
	}
}

// ── Recovery Code Regeneration tests ──────────────────────────────────────

func TestRecoveryCodeRegenerate(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	_, cookies := fullTOTPLogin(t, ctx, srv, ts, "regen@example.com", "test-password-1234")

	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/recovery-codes/regenerate", `{"current_password":"test-password-1234"}`, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("regen: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.RecoveryCodes) != 10 {
		t.Errorf("expected 10 recovery codes, got %d", len(body.RecoveryCodes))
	}
}

func TestRecoveryCodeRegenerateNoMFA(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newMFAServer(t, db)

	doRegister(t, ctx, ts, "regen-nomfa@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "regen-nomfa@example.com", "test-password-1234")
	cookies := authedCookies(t, loginResp)
	loginResp.Body.Close() //nolint:errcheck,gosec

	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/recovery-codes/regenerate", `{"current_password":"test-password-1234"}`, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("regen no MFA: got %d, want 409", resp.StatusCode)
	}
}

func TestRecoveryCodeRegenerateWrongPassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	_, cookies := fullTOTPLogin(t, ctx, srv, ts, "regen-wrong@example.com", "test-password-1234")

	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/recovery-codes/regenerate", `{"current_password":"wrong-password"}`, cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("regen wrong password: got %d, want 401", resp.StatusCode)
	}
}

// ── Remember-device tests ─────────────────────────────────────────────────

func TestRememberDeviceFlow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "remember-dev@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID := uuid.MustParse(reg.UserID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// 1. Login → MFA challenge → verify with remember_device=true.
	loginResp := doLogin(t, ctx, ts, email, password)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q,"remember_device":true}`, code)
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

	// 2. Extract the mfa_device_token cookie.
	deviceToken := cookieValue(verifyResp, "mfa_device_token")
	if deviceToken == "" {
		t.Fatal("expected mfa_device_token cookie from verify with remember_device=true")
	}

	// 3. Login again with device token — expect NO MFA challenge (direct access token).
	loginBody := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	loginReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/login", bytes.NewBufferString(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.AddCookie(&http.Cookie{Name: "mfa_device_token", Value: deviceToken})
	loginResp2, err := ts.Client().Do(loginReq) //nolint:gosec
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	defer loginResp2.Body.Close() //nolint:errcheck,gosec

	if loginResp2.StatusCode != http.StatusOK {
		t.Fatalf("second login: got %d, want 200", loginResp2.StatusCode)
	}

	// Should get access_token directly (no pending token).
	accessToken := cookieValue(loginResp2, "access_token")
	if accessToken == "" {
		t.Error("expected access_token cookie from login with valid device token (MFA bypass)")
	}
	pendingToken := cookieValue(loginResp2, "mfa_pending_token")
	if pendingToken != "" {
		t.Error("should not get mfa_pending_token when device token is valid")
	}
}

func TestRememberDeviceOrgDisallowed(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "no-remember@example.com", "test-password-1234"
	reg := doRegister(t, ctx, ts, email, password)
	userID := uuid.MustParse(reg.UserID)
	orgID := uuid.MustParse(reg.OrgID)
	secret := enrollTOTP(t, ctx, srv, userID)

	// Disable remember-device for the org.
	if _, err := srv.store.UpdateOrgMFASettings(ctx, orgID, false, false, 30); err != nil {
		t.Fatalf("update org settings: %v", err)
	}

	// Login → MFA challenge → verify with remember_device=true.
	loginResp := doLogin(t, ctx, ts, email, password)
	pt := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q,"remember_device":true}`, code)
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

	// No device token should be issued.
	deviceToken := cookieValue(verifyResp, "mfa_device_token")
	if deviceToken != "" {
		t.Error("should not get mfa_device_token when org disallows remember-device")
	}
}

func TestRememberDeviceInvalidatedOnPasswordChange(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	email, password := "dev-pw-change@example.com", "test-password-1234" //nolint:gosec // G101: test credentials
	reg := doRegister(t, ctx, ts, email, password)
	userID := uuid.MustParse(reg.UserID)

	// Create a device token directly in the DB.
	tokenHash := sha256Hex("fake-device-token-123")
	if err := srv.store.CreateRememberDeviceToken(ctx, userID, tokenHash, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatalf("create device token: %v", err)
	}

	// Verify the token is valid.
	valid, err := srv.store.ValidateRememberDeviceToken(ctx, userID, tokenHash)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !valid {
		t.Fatal("device token should be valid before password change")
	}

	// Change password.
	loginResp := doLogin(t, ctx, ts, email, password)
	accessToken := cookieValue(loginResp, "access_token")
	loginResp.Body.Close() //nolint:errcheck,gosec

	changePWReq := authedRequest(t, ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/change-password",
		fmt.Sprintf(`{"current_password":%q,"new_password":"new-secure-password-1"}`, password),
		[]*http.Cookie{{Name: "access_token", Value: accessToken}})
	changePWResp, err := ts.Client().Do(changePWReq) //nolint:gosec
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	defer changePWResp.Body.Close() //nolint:errcheck,gosec
	if changePWResp.StatusCode != http.StatusOK {
		t.Fatalf("change password: got %d, want 200", changePWResp.StatusCode)
	}

	// Verify the device token is now invalid.
	valid, err = srv.store.ValidateRememberDeviceToken(ctx, userID, tokenHash)
	if err != nil {
		t.Fatalf("validate after change: %v", err)
	}
	if valid {
		t.Error("device token should be invalidated after password change")
	}
}

// ── Enrollment pending order enforcement ─────────────────────────────────────

func TestEnrollment_RejectsOutOfOrderPending(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "order-reject@example.com", "test-password-1234")
	userID, err := uuid.Parse(reg.UserID)
	if err != nil {
		t.Fatalf("parse user ID: %v", err)
	}

	// Create a pending token where password_reset comes BEFORE mfa_enrollment_required.
	// The enrollment endpoint should reject this because mfa_enrollment_required is not Pending[0].
	pendingToken, err := auth.IssuePendingToken(
		srv.jwtSecret(),
		userID,
		1,
		[]string{"password_reset", "mfa_enrollment_required"},
		nil,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("issue pending token: %v", err)
	}

	cookies := []*http.Cookie{{Name: "mfa_pending_token", Value: pendingToken}}
	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("out-of-order pending: got %d, want 401", resp.StatusCode)
	}
}

func TestEnrollment_AcceptsCorrectOrder(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "order-accept@example.com", "test-password-1234")
	userID, err := uuid.Parse(reg.UserID)
	if err != nil {
		t.Fatalf("parse user ID: %v", err)
	}

	// Create a pending token where mfa_enrollment_required is the first (and only) step.
	// token_version=1 matches the DB default for a freshly registered user.
	pendingToken, err := auth.IssuePendingToken(
		srv.jwtSecret(),
		userID,
		1,
		[]string{"mfa_enrollment_required"},
		nil,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("issue pending token: %v", err)
	}

	cookies := []*http.Cookie{{Name: "mfa_pending_token", Value: pendingToken}}
	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Errorf("correct order pending: got %d, want 200", resp.StatusCode)
	}
}

func TestEnrollment_RejectsStaleTokenVersion(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newMFAServer(t, db)

	reg := doRegister(t, ctx, ts, "stale-tv-enroll@example.com", "test-password-1234")
	userID, err := uuid.Parse(reg.UserID)
	if err != nil {
		t.Fatalf("parse user ID: %v", err)
	}

	// Create a pending token with token_version=1 (matching the freshly registered user).
	pendingToken, err := auth.IssuePendingToken(
		srv.jwtSecret(),
		userID,
		1,
		[]string{"mfa_enrollment_required"},
		nil,
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("issue pending token: %v", err)
	}

	// Increment token_version (simulating admin MFA reset).
	if _, err := srv.store.IncrementTokenVersion(ctx, userID); err != nil {
		t.Fatalf("increment token version: %v", err)
	}

	// Attempt enrollment with the now-stale pending token.
	cookies := []*http.Cookie{{Name: "mfa_pending_token", Value: pendingToken}}
	req := authedRequest(t, ctx, http.MethodPost, ts.URL+"/api/v1/auth/mfa/totp/setup", "", cookies)
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("setup request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("stale token_version: got %d, want 401", resp.StatusCode)
	}
}
