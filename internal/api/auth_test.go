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
	"testing"
	"time"

	"github.com/google/uuid"

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
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestRegisterFirstUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	body := `{"email":"first@example.com","password":"password123","display_name":"First User"}`
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

	body := `{"email":"dup@example.com","password":"password123"}`

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

// ── Task 26: Login ────────────────────────────────────────────────────────────

func TestLoginSuccess(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "loginok@example.com", "password123")

	resp := doLogin(t, ctx, ts, "loginok@example.com", "password123")
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

	doRegister(t, ctx, ts, "wrongpw@example.com", "password123")

	resp := doLogin(t, ctx, ts, "wrongpw@example.com", "wrongpassword")
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

	resp := doLogin(t, ctx, ts, "nobody@example.com", "password123")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("nonexistent user: got %d, want 401", resp.StatusCode)
	}
}

// ── Task 27: Refresh + Logout ─────────────────────────────────────────────────

func TestRefreshRotates(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "refresh@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "refresh@example.com", "password123")
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
	oldClaims, err := auth.ParseRefreshToken(oldRefreshToken, []byte("regtestsecret"))
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

	doRegister(t, ctx, ts, "grace@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "grace@example.com", "password123")
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

	regOut := doRegister(t, ctx, ts, "theft@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "theft@example.com", "password123")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	firstRefreshToken := cookieValue(loginResp, "refresh_token")

	// Refresh normally (token A consumed, replaced by B).
	req1, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/refresh", nil)
	req1.AddCookie(&http.Cookie{Name: "refresh_token", Value: firstRefreshToken})
	resp1, _ := ts.Client().Do(req1) //nolint:gosec // G704 false positive
	resp1.Body.Close()                //nolint:errcheck,gosec // G104

	// Backdate used_at to simulate grace window expiry.
	oldClaims, err := auth.ParseRefreshToken(firstRefreshToken, []byte("regtestsecret"))
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

	doRegister(t, ctx, ts, "logout@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "logout@example.com", "password123")
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

	regOut := doRegister(t, ctx, ts, "me@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "me@example.com", "password123")
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

	doRegister(t, ctx, ts, "changepw@example.com", "oldpassword")
	loginResp := doLogin(t, ctx, ts, "changepw@example.com", "oldpassword")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	body := `{"current_password":"oldpassword","new_password":"newpassword1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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
	oldLoginResp := doLogin(t, ctx, ts, "changepw@example.com", "oldpassword")
	oldLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	if oldLoginResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("old password login after change: got %d, want 401", oldLoginResp.StatusCode)
	}

	// New password login should succeed.
	newLoginResp := doLogin(t, ctx, ts, "changepw@example.com", "newpassword1")
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

	doRegister(t, ctx, ts, "wrongcurrent@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "wrongcurrent@example.com", "password123")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")

	body := `{"current_password":"wrongcurrent","new_password":"newpassword1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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

	doRegister(t, ctx, ts, "revoke@example.com", "password123")
	loginResp := doLogin(t, ctx, ts, "revoke@example.com", "password123")
	loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	refreshToken := cookieValue(loginResp, "refresh_token")

	// Change password — increments token_version.
	body := `{"current_password":"password123","new_password":"newpassword1"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/change-password",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
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

// Suppress unused import warning for time (used in tests above).
var _ = time.Now
