// ABOUTME: Integration tests for auth HTTP handlers (register, login, refresh, logout, me).
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// cookieValue extracts the value of a named cookie from an HTTP response.
// Returns "" if not found.
func cookieValue(resp *http.Response, name string) string {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// doRegister registers a user and returns the parsed response body.
// Fails the test if the response status is not 201.
func doRegister(t *testing.T, ctx context.Context, ts *httptest.Server, email, password string) struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
} {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("register request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register: got %d, want 201", resp.StatusCode)
	}
	var out struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("register decode: %v", err)
	}
	return out
}

// doLogin logs in and returns the response (caller must close Body).
func doLogin(t *testing.T, ctx context.Context, ts *httptest.Server, email, password string) *http.Response {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	return resp
}

// newRegisterServer creates a full Server + httptest.Server for auth handler tests.
func newRegisterServer(t *testing.T, db *testutil.TestDB, regMode string) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "regtestsecret",
		RegistrationMode:    regMode,
		Argon2MaxConcurrent: 5,
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

func TestRegisterFirstUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	body := `{"email":"first@example.com","password":"test-password-1234","display_name":"First User"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: got %d, want 201", resp.StatusCode)
	}

	var respBody struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respBody.UserID == "" {
		t.Error("user_id missing from response")
	}
	if respBody.OrgID == "" {
		t.Error("org_id missing from response (first user should get a default org)")
	}

	// Verify DB state.
	userID, err := uuid.Parse(respBody.UserID)
	if err != nil {
		t.Fatalf("parse user_id: %v", err)
	}
	orgID, err := uuid.Parse(respBody.OrgID)
	if err != nil {
		t.Fatalf("parse org_id: %v", err)
	}

	user, err := db.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		t.Fatalf("user not found in DB: %v", err)
	}
	if user.Email != "first@example.com" {
		t.Errorf("user email = %q, want %q", user.Email, "first@example.com")
	}

	roleStr, err := db.GetOrgMemberRole(ctx, orgID, userID)
	if err != nil || roleStr == nil {
		t.Fatalf("org member role not found: %v", err)
	}
	if *roleStr != "owner" {
		t.Errorf("org member role = %q, want %q", *roleStr, "owner")
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	body := `{"email":"dup@example.com","password":"test-password-1234"}`

	// First registration — should succeed.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first registration: got %d, want 201", resp.StatusCode)
	}

	// Second registration with same email — should return 409.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104: body close in test
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("duplicate email: got %d, want 409", resp2.StatusCode)
	}
}

// ── Rate limiting on auth endpoints ──────────────────────────────────────────

func TestLoginRateLimited(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	srv, ts := newRegisterServer(t, db, "open")
	doRegister(t, ctx, ts, "ratelimit@example.com", "test-password-1234")

	// Replace the rate limiter with a tight burst of 2 AFTER registration.
	srv.rateLimiter.Stop()
	srv.rateLimiter = newIPRateLimiter(rate.Limit(1), 2, time.Minute)

	// First 2 logins: allowed (burst=2).
	for i := 1; i <= 2; i++ {
		resp := doLogin(t, ctx, ts, "ratelimit@example.com", "test-password-1234")
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("login %d: got 429 too early (burst should allow 2)", i)
		}
	}

	// 3rd login: rate limited.
	resp := doLogin(t, ctx, ts, "ratelimit@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("login 3: got %d, want 429", resp.StatusCode)
	}
}

func TestRegisterRateLimited(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	srv, ts := newRegisterServer(t, db, "open")

	// Replace the rate limiter with burst=1 and near-zero replenishment rate.
	// rate.Every(time.Hour) ensures tokens don't replenish between requests
	// (the first request includes argon2 hashing which can take >1s in CI).
	srv.rateLimiter.Stop()
	srv.rateLimiter = newIPRateLimiter(rate.Every(time.Hour), 1, time.Minute)

	// First registration: allowed.
	body := `{"email":"rl1@example.com","password":"test-password-1234"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatal("first register should not be rate limited")
	}

	// Second registration: rate limited.
	body2 := `{"email":"rl2@example.com","password":"test-password-1234"}`
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body2))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second register: got %d, want 429", resp2.StatusCode)
	}
}

// ── Task 26: Login ────────────────────────────────────────────────────────────

func TestLoginSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "loginok@example.com", "test-password-1234")

	resp := doLogin(t, ctx, ts, "loginok@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", resp.StatusCode)
	}
	if cookieValue(resp, "access_token") == "" {
		t.Error("access_token cookie not set")
	}
	if cookieValue(resp, "refresh_token") == "" {
		t.Error("refresh_token cookie not set")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "wrongpw@example.com", "test-password-1234")

	resp := doLogin(t, ctx, ts, "wrongpw@example.com", "test-wrong-password")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: got %d, want 401", resp.StatusCode)
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	resp := doLogin(t, ctx, ts, "nobody@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("nonexistent user: got %d, want 401", resp.StatusCode)
	}
}

func TestLoginOAuthOnlyAccount(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Create an OAuth-only user directly in DB (no password hash).
	_, err := db.CreateUser(ctx, "oauth-login@example.com", "OAuth User", "", 0)
	if err != nil {
		t.Fatalf("create oauth user: %v", err)
	}

	// Attempt login with password — should get 401 (same as wrong password, no enumeration).
	resp := doLogin(t, ctx, ts, "oauth-login@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("login on OAuth-only account: got %d, want 401", resp.StatusCode)
	}
}

func TestLoginDisabledUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "disabled@example.com", "test-password-1234")

	// Disable the user via admin store method.
	userID, err := uuid.Parse(reg.UserID)
	if err != nil {
		t.Fatalf("parse user_id: %v", err)
	}
	if _, err := db.AdminDisableUser(ctx, userID); err != nil {
		t.Fatalf("AdminDisableUser: %v", err)
	}

	// Login with correct credentials should return 401 (same as nonexistent user).
	resp := doLogin(t, ctx, ts, "disabled@example.com", "test-password-1234")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled user login: got %d, want 401", resp.StatusCode)
	}

	// Verify the error message matches the nonexistent-user response.
	var errBody struct {
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if errBody.Detail != "invalid credentials" {
		t.Errorf("error detail = %q, want %q", errBody.Detail, "invalid credentials")
	}

	// Verify no auth cookies were set.
	if cookieValue(resp, "access_token") != "" {
		t.Error("access_token cookie should not be set for disabled user")
	}
	if cookieValue(resp, "refresh_token") != "" {
		t.Error("refresh_token cookie should not be set for disabled user")
	}
}

func TestLoginDisabledUser_RecordsLockoutFailure(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "disabled-lockout@example.com", "test-password-1234")

	userID, err := uuid.Parse(reg.UserID)
	if err != nil {
		t.Fatalf("parse user_id: %v", err)
	}
	if _, err := db.AdminDisableUser(ctx, userID); err != nil {
		t.Fatalf("AdminDisableUser: %v", err)
	}

	// Multiple login attempts on a disabled account should trigger lockout.
	for i := 0; i < 6; i++ {
		resp := doLogin(t, ctx, ts, "disabled-lockout@example.com", "test-password-1234")
		resp.Body.Close() //nolint:errcheck,gosec // G104
	}

	// Verify lockout was recorded (the lockout manager should have failures).
	allowed, _ := srv.lockout.Check(ctx, "disabled-lockout@example.com")
	if allowed {
		t.Error("expected lockout after repeated disabled-user login attempts")
	}
}

// ── Task 27: Refresh + Logout ─────────────────────────────────────────────────

func TestRefreshRotates(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "refresh@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "refresh@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d", loginResp.StatusCode)
	}
	oldRefreshToken := cookieValue(loginResp, "refresh_token")
	if oldRefreshToken == "" {
		t.Fatal("no refresh_token cookie after login")
	}

	// Refresh: should issue new tokens and mark old JTI used.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: oldRefreshToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh: got %d, want 200", resp.StatusCode)
	}
	newAccessToken := cookieValue(resp, "access_token")
	newRefreshToken := cookieValue(resp, "refresh_token")
	if newAccessToken == "" {
		t.Error("new access_token cookie not set after refresh")
	}
	if newRefreshToken == "" || newRefreshToken == oldRefreshToken {
		t.Error("new refresh_token should differ from old")
	}

	// Verify old JTI is marked used in DB.
	oldClaims, err := auth.ParseRefreshToken(oldRefreshToken, []byte("regtestsecret"), nil)
	if err != nil {
		t.Fatalf("parse old refresh token: %v", err)
	}
	stored, err := db.GetRefreshToken(ctx, oldClaims.JTI)
	if err != nil || stored == nil {
		t.Fatalf("get stored token: %v", err)
	}
	if !stored.UsedAt.Valid {
		t.Error("old refresh token should be marked used")
	}
}

func TestRefreshGraceWindow(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "grace@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "grace@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	firstRefreshToken := cookieValue(loginResp, "refresh_token")

	// First refresh: consumes the token, returns new tokens.
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req1.AddCookie(&http.Cookie{Name: "refresh_token", Value: firstRefreshToken})
	resp1, err := ts.Client().Do(req1) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	resp1.Body.Close() //nolint:errcheck,gosec // G104
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first refresh: got %d", resp1.StatusCode)
	}

	// Second refresh with the SAME (now-used) token — within grace window → 200.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "refresh_token", Value: firstRefreshToken})
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("grace refresh: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("grace window refresh: got %d, want 200", resp2.StatusCode)
	}
}

func TestRefreshTheftDetection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	regOut := doRegister(t, ctx, ts, "theft@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "theft@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	firstRefreshToken := cookieValue(loginResp, "refresh_token")

	// Refresh normally (token A consumed, replaced by B).
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req1.AddCookie(&http.Cookie{Name: "refresh_token", Value: firstRefreshToken})
	resp1, _ := ts.Client().Do(req1) //nolint:gosec // G704 false positive
	resp1.Body.Close()                //nolint:errcheck,gosec // G104

	// Backdate used_at to simulate grace window expiry.
	oldClaims, err := auth.ParseRefreshToken(firstRefreshToken, []byte("regtestsecret"), nil)
	if err != nil {
		t.Fatalf("parse refresh token: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx,
		"UPDATE refresh_tokens SET used_at = now() - interval '2 minutes' WHERE jti = $1",
		oldClaims.JTI); err != nil {
		t.Fatalf("backdate used_at: %v", err)
	}

	// Re-use the same token after grace window — theft detected → 401.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "refresh_token", Value: firstRefreshToken})
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("theft re-use: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("theft detection: got %d, want 401", resp2.StatusCode)
	}

	// Verify token_version was incremented (further refresh with old tokens also fails).
	userID := uuid.MustParse(regOut.UserID)
	user, err := db.GetUserByID(ctx, userID)
	if err != nil || user == nil {
		t.Fatalf("get user: %v", err)
	}
	if user.TokenVersion <= 1 {
		t.Errorf("token_version should have been incremented, got %d", user.TokenVersion)
	}
}

func TestLogoutClearsCookies(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "logout@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "logout@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	refreshToken := cookieValue(loginResp, "refresh_token")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Errorf("logout: got %d, want 200", resp.StatusCode)
	}

	// Cookies should be cleared (MaxAge=0 or negative in Set-Cookie response).
	for _, c := range resp.Cookies() {
		if (c.Name == "access_token" || c.Name == "refresh_token") && c.MaxAge >= 0 && c.Value != "" {
			t.Errorf("cookie %q not cleared after logout (MaxAge=%d, Value=%q)", c.Name, c.MaxAge, c.Value)
		}
	}
}

// ── Task 28: /auth/me ─────────────────────────────────────────────────────────

func TestGetMe(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	regOut := doRegister(t, ctx, ts, "me@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "me@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get me: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get me: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		UserID      string `json:"user_id"`
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
		Orgs        []struct {
			OrgID string `json:"org_id"`
			Name  string `json:"name"`
			Role  string `json:"role"`
		} `json:"orgs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if body.UserID != regOut.UserID {
		t.Errorf("user_id = %q, want %q", body.UserID, regOut.UserID)
	}
	if body.Email != "me@example.com" {
		t.Errorf("email = %q, want %q", body.Email, "me@example.com")
	}
	if len(body.Orgs) != 1 {
		t.Errorf("orgs count = %d, want 1 (first user gets a default org)", len(body.Orgs))
	}
	if len(body.Orgs) > 0 && body.Orgs[0].Role != "owner" {
		t.Errorf("org role = %q, want %q", body.Orgs[0].Role, "owner")
	}
}

// ── Task 29: Change password ──────────────────────────────────────────────────

func TestChangePassword_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "changepw@example.com", "test-old-password-1")
	loginResp := doLogin(t, ctx, ts, "changepw@example.com", "test-old-password-1")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	body := `{"current_password":"test-old-password-1","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change-password: got %d, want 200", resp.StatusCode)
	}

	// Old password login should now fail.
	oldLoginResp := doLogin(t, ctx, ts, "changepw@example.com", "test-old-password-1")
	oldLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	if oldLoginResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password login after change: got %d, want 401", oldLoginResp.StatusCode)
	}

	// New password login should succeed.
	newLoginResp := doLogin(t, ctx, ts, "changepw@example.com", "test-new-password-1")
	newLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	if newLoginResp.StatusCode != http.StatusOK {
		t.Errorf("new password login after change: got %d, want 200", newLoginResp.StatusCode)
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "wrongcurrent@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "wrongcurrent@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	body := `{"current_password":"wrongcurrent","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong current password: got %d, want 401", resp.StatusCode)
	}
}

func TestChangePassword_InvalidatesRefreshTokens(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "revoke@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "revoke@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	refreshToken := cookieValue(loginResp, "refresh_token")

	// Change password — increments token_version.
	body := `{"current_password":"test-password-1234","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change-password: got %d", resp.StatusCode)
	}

	// Old refresh token should now be rejected (token_version mismatch).
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("refresh after change-password: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("old refresh after change-password: got %d, want 401", resp2.StatusCode)
	}
}

// ── Registration mode ─────────────────────────────────────────────────────────

func TestRegisterInviteOnlyMode(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "invite-only")

	// Bootstrap first user (allowed even in invite-only mode).
	doRegister(t, ctx, ts, "bootstrap@example.com", "test-password-1234")

	// Second user registration should be blocked.
	body := `{"email":"blocked@example.com","password":"test-password-1234"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("invite-only register: got %d, want 403", resp.StatusCode)
	}
}

// ── Refresh edge cases ────────────────────────────────────────────────────────

func TestRefreshMissingCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Refresh with no cookie at all.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh without cookie: got %d, want 401", resp.StatusCode)
	}
}

func TestRefreshInvalidToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Refresh with garbage token.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "totally-invalid-jwt"})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh with invalid token: got %d, want 401", resp.StatusCode)
	}
}

func TestRefreshRevokedTokenVersion(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	regOut := doRegister(t, ctx, ts, "tvrev@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "tvrev@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	refreshToken := cookieValue(loginResp, "refresh_token")

	// Manually increment token_version to simulate password change or admin logout-all.
	userID := uuid.MustParse(regOut.UserID)
	if _, err := db.IncrementTokenVersion(ctx, userID); err != nil {
		t.Fatalf("increment token version: %v", err)
	}

	// The refresh token's token_version no longer matches → 401.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("refresh with revoked token_version: got %d, want 401", resp.StatusCode)
	}
}

// ── /auth/me edge cases ───────────────────────────────────────────────────────

func TestGetMe_NoCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/me", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get me: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("me without cookie: got %d, want 401", resp.StatusCode)
	}
}

func TestGetMe_InvalidToken(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "garbage-token"})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get me: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("me with invalid token: got %d, want 401", resp.StatusCode)
	}
}

// ── Change password edge cases ────────────────────────────────────────────────

func TestChangePassword_NoCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	body := `{"current_password":"anything","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("change-password without auth: got %d, want 401", resp.StatusCode)
	}
}

func TestChangePassword_OAuthOnlyAccount(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Create an OAuth-only user (no password hash).
	oauthUser, err := db.CreateUser(ctx, "oauthonly@example.com", "OAuth User", "", 0)
	if err != nil {
		t.Fatalf("create oauth user: %v", err)
	}

	// Issue a valid access token for this user.
	accessToken, err := auth.IssueAccessToken([]byte("regtestsecret"), oauthUser.ID, 0, accessTokenTTL)
	if err != nil {
		t.Fatalf("issue access token: %v", err)
	}

	body := `{"current_password":"something","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("change-password on OAuth-only account: got %d, want 400", resp.StatusCode)
	}
}

// ── Invitation edge cases ─────────────────────────────────────────────────────

func TestGetInvitation_Expired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(loginResp, "access_token")

	// Create invitation.
	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "viewer")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
	}

	// Backdate the expiry to simulate expired invitation.
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations: err=%v, len=%d", err, len(invitations))
	}
	token := invitations[0].Token
	if _, err := db.DB().ExecContext(ctx,
		"UPDATE org_invitations SET expires_at = now() - interval '1 hour' WHERE token = $1",
		token); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}

	resp := doGetInvitation(t, ctx, ts, token)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusGone {
		t.Errorf("expired invitation: got %d, want 410", resp.StatusCode)
	}
}

func TestAcceptInvitation_Expired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	doRegister(t, ctx, ts, "bob@example.com", "test-password-1234")

	// Alice creates invitation for bob.
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104

	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations: err=%v, len=%d", err, len(invitations))
	}
	invToken := invitations[0].Token

	// Backdate the expiry.
	if _, err := db.DB().ExecContext(ctx,
		"UPDATE org_invitations SET expires_at = now() - interval '1 hour' WHERE token = $1",
		invToken); err != nil {
		t.Fatalf("backdate expires_at: %v", err)
	}

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	resp := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusGone {
		t.Errorf("accept expired invitation: got %d, want 410", resp.StatusCode)
	}
}

func TestAcceptInvitation_NoCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/invitations/sometoken/accept", nil)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("accept without auth: got %d, want 401", resp.StatusCode)
	}
}

// ── Auth providers endpoint tests ─────────────────────────────────────────────

func TestAuthProvidersNoOAuth(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/providers", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		GitHub           bool   `json:"github"`
		Google           bool   `json:"google"`
		RegistrationMode string `json:"registration_mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.GitHub {
		t.Error("github should be false when not configured")
	}
	if body.Google {
		t.Error("google should be false when not configured")
	}
	if body.RegistrationMode != "open" {
		t.Errorf("registration_mode: got %q, want %q", body.RegistrationMode, "open")
	}
}

func TestAuthProvidersInviteOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "invite-only")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/providers", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		RegistrationMode string `json:"registration_mode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if body.RegistrationMode != "invite-only" {
		t.Errorf("registration_mode: got %q, want %q", body.RegistrationMode, "invite-only")
	}
}

func TestRegister_InviteOnlyBootstrap(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "invite-only")
	ctx := context.Background()

	// First registration in invite-only mode should succeed (bootstrap).
	body := `{"email":"first@example.com","password":"super-secret-pass-16ch"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first register in invite-only: got %d, want 201", resp.StatusCode)
	}

	var out struct {
		UserID string `json:"user_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.UserID == "" {
		t.Fatal("expected user_id in response")
	}
	if out.OrgID == "" {
		t.Fatal("expected org_id in bootstrap response")
	}
}

func TestRegister_InviteOnlyAfterBootstrap(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "invite-only")
	ctx := context.Background()

	// Bootstrap first user.
	body := `{"email":"first@example.com","password":"super-secret-pass-16ch"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("bootstrap register: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap: got %d, want 201", resp.StatusCode)
	}

	// Second registration should be blocked.
	body2 := `{"email":"second@example.com","password":"super-secret-pass-16ch"}`
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body2))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("second register in invite-only: got %d, want 403", resp2.StatusCode)
	}
}

// ── Bootstrap race condition (B1, B4, B9) ─────────────────────────────────────

func TestRegister_InviteOnly_ConcurrentBootstrap(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	_, ts := newRegisterServer(t, db, "invite-only")
	ctx := context.Background()

	// Two concurrent registrations on a fresh DB in invite-only mode
	// should result in exactly one registered user (the bootstrap user).
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready
			email := fmt.Sprintf("bootstrap%d@example.com", idx)
			body := fmt.Sprintf(`{"email":%q,"password":"super-secret-pass-16ch"}`, email)
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
				ts.URL+"/api/v1/auth/register", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
			if err != nil {
				t.Errorf("register request %d: %v", idx, err)
				return
			}
			defer resp.Body.Close() //nolint:errcheck,gosec // G104
			results[idx] = resp.StatusCode
		}(i)
	}
	close(ready)
	wg.Wait()

	// Exactly one should succeed (201), one should be rejected (403).
	successes := 0
	for _, code := range results {
		if code == http.StatusCreated {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 success, got %d (results: %v)", successes, results)
	}
}

// TestAcceptInvitation_ConcurrentAccept verifies that two simultaneous accepts
// both return 200 instead of one returning 500 (B2).
func TestAcceptInvitation_ConcurrentAccept(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	doRegister(t, ctx, ts, "bob@example.com", "test-password-1234")

	// Alice creates invitation for bob.
	aliceLoginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	createResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "bob@example.com", "member")
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create invitation: got %d, want 202", createResp.StatusCode)
	}

	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) != 1 {
		t.Fatalf("list invitations: err=%v, len=%d", err, len(invitations))
	}
	invToken := invitations[0].Token

	bobLoginResp := doLogin(t, ctx, ts, "bob@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	// Two concurrent accepts using a barrier.
	ready := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready
			resp := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
			defer resp.Body.Close() //nolint:errcheck,gosec // G104
			results[idx] = resp.StatusCode
		}(i)
	}
	close(ready)
	wg.Wait()

	// Both should return 200 (idempotent).
	for i, code := range results {
		if code != http.StatusOK {
			t.Errorf("accept[%d]: got %d, want 200", i, code)
		}
	}
}

// ── force_password_reset handler tests ────────────────────────────────────────

func TestChangePassword_ClearsForcePasswordReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "forcereset-clear@example.com", "test-old-password-1")

	// Set force_password_reset flag via admin store method.
	user, err := db.GetUserByEmail(ctx, "forcereset-clear@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	// Verify flag is set.
	status, err := db.GetUserAuthStatus(ctx, user.ID)
	if err != nil {
		t.Fatalf("get auth status: %v", err)
	}
	if !status.ForcePasswordReset {
		t.Fatal("force_password_reset should be true before password change")
	}

	// Login and change password.
	loginResp := doLogin(t, ctx, ts, "forcereset-clear@example.com", "test-old-password-1")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	body := `{"current_password":"test-old-password-1","new_password":"test-new-password-1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("change-password: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("change-password: got %d, want 200", resp.StatusCode)
	}

	// Verify flag is cleared.
	status, err = db.GetUserAuthStatus(ctx, user.ID)
	if err != nil {
		t.Fatalf("get auth status after change: %v", err)
	}
	if status.ForcePasswordReset {
		t.Error("force_password_reset should be false after password change")
	}
}

func TestMe_IncludesForcePasswordReset(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "forcereset-me@example.com", "test-password-1234")

	// Set force_password_reset flag.
	user, err := db.GetUserByEmail(ctx, "forcereset-me@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	loginResp := doLogin(t, ctx, ts, "forcereset-me@example.com", "test-password-1234")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get me: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get me: got %d, want 200", resp.StatusCode)
	}

	var body struct {
		ForcePasswordReset bool `json:"force_password_reset"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if !body.ForcePasswordReset {
		t.Error("force_password_reset should be true in /auth/me response")
	}
}

// Suppress unused import warning for time (used in tests above).
var _ = time.Now
