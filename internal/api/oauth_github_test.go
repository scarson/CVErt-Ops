// ABOUTME: Integration tests for the GitHub OAuth2 login flow.
// ABOUTME: Uses a mock GitHub API server to test the init/callback handlers end-to-end.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newGitHubMockServer creates a mock server simulating GitHub's OAuth and API endpoints.
func newGitHubMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"access_token": "gho_test_access_token",
				"token_type":   "bearer",
				"scope":        "user:email",
			})
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"id":    12345,
				"login": "testghuser",
				"name":  "Test GitHub User",
			})
		case "/user/emails":
			_ = json.NewEncoder(w).Encode([]map[string]any{ //nolint:gosec // G104: test mock server
				{"email": "ghuser@example.com", "primary": true, "verified": true},
				{"email": "ghuser-noreply@users.noreply.github.com", "primary": false, "verified": true},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// newGitHubTestServer sets up an API server with a custom GitHub OAuth config pointing to mock.
func newGitHubTestServer(t *testing.T, db *testutil.TestDB, ghMock *httptest.Server) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:           "ghtest-secret-32-bytes-minimum-aa",
		Argon2MaxConcurrent: 5,
		GitHubClientID:      "test-gh-client-id",
		GitHubClientSecret:  "test-gh-secret",
		ExternalURL:         "http://localhost",
		RegistrationMode:    "open",
		FrontendURL:         "http://localhost:5173",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Override GitHub OAuth config to route through the mock server.
	srv.ghOAuth = &oauth2.Config{
		ClientID:     "test-gh-client-id",
		ClientSecret: "test-gh-secret",
		RedirectURL:  "http://localhost/api/v1/auth/oauth/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  ghMock.URL + "/login/oauth/authorize",
			TokenURL: ghMock.URL + "/login/oauth/access_token",
		},
		Scopes: []string{"user:email"},
	}
	srv.ghAPIBaseURL = ghMock.URL
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return srv, ts
}

// noRedirect is a CheckRedirect func that prevents following redirects.
func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func TestGitHubInit_NotConfigured(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:           "ghtest-secret-32-bytes-minimum-aa",
		Argon2MaxConcurrent: 5,
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	client := ts.Client()
	client.CheckRedirect = noRedirect
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("GET /auth/oauth/github: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}

func TestGitHubInit_Configured(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("GET /auth/oauth/github: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login/oauth/authorize") {
		t.Errorf("Location = %q, want GitHub authorize URL", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected oauth_state cookie, not found")
	}
	if !stateCookie.HttpOnly {
		t.Error("oauth_state cookie must be HttpOnly")
	}
}

func TestGitHubCallback_NewUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	// Step 1: Get init redirect to capture state cookie.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	// Step 2: Call callback with state cookie + fake code.
	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://localhost:5173" {
		t.Errorf("Location = %q, want %q", got, "http://localhost:5173")
	}

	// Verify auth cookies are set.
	var accessCookie, refreshCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "access_token":
			accessCookie = c
		case "refresh_token":
			refreshCookie = c
		}
	}
	if accessCookie == nil {
		t.Error("expected access_token cookie")
	}
	if refreshCookie == nil {
		t.Error("expected refresh_token cookie")
	}

	// Verify user was created.
	user, err := db.GetUserByProviderID(t.Context(), "github", "12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to be created")
	}
	if user.Email != "ghuser@example.com" {
		t.Errorf("user.Email = %q, want %q", user.Email, "ghuser@example.com")
	}
}

func TestGitHubCallback_ExistingUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	// Pre-create the user and link identity.
	ctx := t.Context()
	existingUser, err := db.CreateUser(ctx, "old@example.com", "Old Name", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpsertUserIdentity(ctx, existingUser.ID, "github", "12345", "old@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	client := ts.Client()
	client.CheckRedirect = noRedirect

	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}

	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://localhost:5173" {
		t.Errorf("Location = %q, want %q", got, "http://localhost:5173")
	}

	// Verify the same user was returned (looked up by provider ID, not email).
	user, err := db.GetUserByProviderID(t.Context(), "github", "12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to exist")
	}
	if user.ID != existingUser.ID {
		t.Errorf("user.ID = %v, want %v (should match existing user by provider ID)", user.ID, existingUser.ID)
	}
}

func TestGitHubCallback_InviteOnlyRejectsNewUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)

	// Create test server with invite-only registration mode.
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:           "ghtest-secret-32-bytes-minimum-aa",
		Argon2MaxConcurrent: 5,
		GitHubClientID:      "test-gh-client-id",
		GitHubClientSecret:  "test-gh-secret",
		ExternalURL:         "http://localhost",
		RegistrationMode:    "invite-only",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.ghOAuth = &oauth2.Config{
		ClientID:     "test-gh-client-id",
		ClientSecret: "test-gh-secret",
		RedirectURL:  "http://localhost/api/v1/auth/oauth/github/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  ghMock.URL + "/login/oauth/authorize",
			TokenURL: ghMock.URL + "/login/oauth/access_token",
		},
		Scopes: []string{"user:email"},
	}
	srv.ghAPIBaseURL = ghMock.URL
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	// Step 1: Init to capture state cookie.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	// Step 2: Call callback — no user exists, registration mode is invite-only.
	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}

	// Verify no user was created.
	user, err := db.GetUserByProviderID(t.Context(), "github", "12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if user != nil {
		t.Error("expected no user to be created in invite-only mode")
	}
}

func TestGitHubCallback_EmailCollisionReturns409(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	// Pre-create a user with the same email via native registration (no GitHub identity linked).
	ctx := t.Context()
	_, err := db.CreateUser(ctx, "ghuser@example.com", "Native User", "somehash", 1)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Step 1: Init to capture state cookie.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	// Step 2: Callback — CreateUser should fail with unique violation on email.
	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func TestGitHubCallback_UpdatesLastLogin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	// Pre-create user with GitHub identity linked.
	ctx := t.Context()
	existingUser, err := db.CreateUser(ctx, "old@example.com", "Old Name", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpsertUserIdentity(ctx, existingUser.ID, "github", "12345", "old@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	// Verify last_login_at is initially null.
	userBefore, err := db.GetUserByID(ctx, existingUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if userBefore.LastLoginAt.Valid {
		t.Fatal("expected last_login_at to be null before login")
	}

	// Do OAuth callback.
	client := ts.Client()
	client.CheckRedirect = noRedirect

	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}

	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (redirect to frontend)", resp.StatusCode)
	}

	// Verify last_login_at is now set.
	userAfter, err := db.GetUserByID(ctx, existingUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !userAfter.LastLoginAt.Valid {
		t.Error("expected last_login_at to be set after OAuth login")
	}
}

func TestGitHubCallback_InvalidState(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect

	// Call callback without a state cookie (missing cookie = invalid state).
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/api/v1/auth/oauth/github/callback?code=fake-code&state=wrong-state", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGitHubCallback_MismatchedStateCookie(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect

	// Init to get a valid state cookie.
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	// Callback with the cookie but a DIFFERENT state in the query string.
	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=tampered-state"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGitHubCallback_NoVerifiedPrimaryEmail(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	// Mock server that returns no verified primary email.
	noEmailMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/oauth/access_token":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"access_token": "gho_test_access_token",
				"token_type":   "bearer",
				"scope":        "user:email",
			})
		case "/user":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"id":    99999,
				"login": "noemail",
				"name":  "",
			})
		case "/user/emails":
			// Only unverified emails — no verified primary.
			_ = json.NewEncoder(w).Encode([]map[string]any{ //nolint:gosec // G104: test mock server
				{"email": "unverified@example.com", "primary": true, "verified": false},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(noEmailMock.Close)

	_, ts := newGitHubTestServer(t, db, noEmailMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect

	// Init.
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	// Callback.
	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no verified email: status = %d, want 400", resp.StatusCode)
	}
}

func TestGitHubCallback_IdentityLinking(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ghMock := newGitHubMockServer(t)
	_, ts := newGitHubTestServer(t, db, ghMock)

	// Pre-create a user with a DIFFERENT email and link it to the same GitHub ID.
	// On next OAuth login, the existing user should be found by provider ID
	// (not email), and the email should be updated via UpsertUserIdentity.
	ctx := t.Context()
	existingUser, err := db.CreateUser(ctx, "old-gh@example.com", "Old GH User", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpsertUserIdentity(ctx, existingUser.ID, "github", "12345", "old-gh@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	client := ts.Client()
	client.CheckRedirect = noRedirect

	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/github", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		if c.Name == "oauth_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("no oauth_state cookie from init")
	}

	callbackURL := ts.URL + "/api/v1/auth/oauth/github/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://localhost:5173" {
		t.Errorf("Location = %q, want %q", got, "http://localhost:5173")
	}

	// Verify the same user was returned (looked up by provider ID, not email).
	user, err := db.GetUserByProviderID(t.Context(), "github", "12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to exist")
	}
	if user.ID != existingUser.ID {
		t.Errorf("user.ID = %v, want %v (should match existing user by provider ID)", user.ID, existingUser.ID)
	}
}
