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

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/crypto"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newMFAServer creates a server with MFA config and an SSO encryption key.
func newMFAServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:              "mfa-test-secret-at-least-32-bytes",
		RegistrationMode:       "open",
		Argon2MaxConcurrent:    5,
		MFAEmailOTPTTL:         10 * time.Minute,
		MFAEmailOTPMaxPerHour:  5,
		MFAChallengeMaxAttempts: 3,
		MFAPendingTokenTTL:     5 * time.Minute,
		SSOEncryptionKey:       "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // 64 hex chars = 32 bytes
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
	secret := "JBSWY3DPEHPK3PXP" // standard test secret
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
	defer resp.Body.Close() //nolint:errcheck,gosec

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
	defer resp.Body.Close() //nolint:errcheck,gosec

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
	defer resp.Body.Close() //nolint:errcheck,gosec

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
	if _, err := db.Store.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force password reset: %v", err)
	}

	resp := doLogin(t, ctx, ts, "forcereset@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec

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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp.Body.Close() //nolint:errcheck

	reqBody := `{"method":"totp"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/challenge", bytes.NewBufferString(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pendingToken})
	resp, err := ts.Client().Do(req) //nolint:gosec
	if err != nil {
		t.Fatalf("challenge request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	loginResp1.Body.Close() //nolint:errcheck

	verifyBody := fmt.Sprintf(`{"method":"totp","code":%q}`, code)
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req1.Header.Set("Content-Type", "application/json")
	req1.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt1})
	resp1, err := ts.Client().Do(req1) //nolint:gosec
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	resp1.Body.Close() //nolint:errcheck
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first verify: got %d, want 200", resp1.StatusCode)
	}

	// Second verify with same code — should fail (replay).
	loginResp2 := doLogin(t, ctx, ts, "replay@example.com", "test-password-1234")
	pt2 := cookieValue(loginResp2, "mfa_pending_token")
	loginResp2.Body.Close() //nolint:errcheck

	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/mfa/verify", bytes.NewBufferString(verifyBody))
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "mfa_pending_token", Value: pt2})
	resp2, err := ts.Client().Do(req2) //nolint:gosec
	if err != nil {
		t.Fatalf("second verify: %v", err)
	}
	resp2.Body.Close() //nolint:errcheck
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
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	if _, err := db.Store.AdminForcePasswordReset(ctx, userID); err != nil {
		t.Fatalf("force password reset: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "remaining@example.com", "test-password-1234")
	pendingToken := cookieValue(loginResp, "mfa_pending_token")
	loginResp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
