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

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
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

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Verify the same user ID is returned (not a new user).
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.UserID != existingUser.ID.String() {
		t.Errorf("user_id = %q, want %q", body.UserID, existingUser.ID.String())
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
