// ABOUTME: Tests for RequireAuthenticated middleware (JWT cookie + API key Bearer).
// ABOUTME: Uses package api to access unexported context keys and Server fields.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// assertRFC9457Response checks that the response has Content-Type application/problem+json
// and a valid JSON body with status, title, and detail fields per RFC 9457.
func assertRFC9457Response(t *testing.T, resp *http.Response, wantStatus int) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var problem struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(body, &problem); err != nil {
		t.Fatalf("decode problem+json: %v (body: %s)", err, string(body))
	}
	if problem.Status != wantStatus {
		t.Errorf("problem.status = %d, want %d", problem.Status, wantStatus)
	}
	if problem.Title == "" {
		t.Error("problem.title is empty")
	}
	if problem.Detail == "" {
		t.Error("problem.detail is empty")
	}
}

// newAuthTestServer builds a minimal Server with the given JWTSecret and optional store.
func newAuthTestServer(t *testing.T, jwtSecret string, db *testutil.TestDB) *Server {
	t.Helper()
	cfg := &config.Config{JWTSecret: jwtSecret} //nolint:exhaustruct // test: only JWT secret needed
	var srv *Server
	if db != nil {
		srv, _ = NewServer(db.Store, cfg, ServerDeps{})
	} else {
		srv, _ = NewServer(nil, cfg, ServerDeps{})
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestRequireAuthenticated_NoCredentials_401(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer(t, "testsecret", nil)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credentials: got %d, want 401", resp.StatusCode)
	}
	assertRFC9457Response(t, resp, http.StatusUnauthorized)
}

func TestRequireAuthenticated_JWT_Valid(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "jwtvalid@example.com", "JWTValid", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := []byte("testsecret")
	token, err := auth.IssueAccessToken(secret, user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var gotUserID uuid.UUID
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = r.Context().Value(ctxUserID).(uuid.UUID)
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid JWT: got %d, want 200", resp.StatusCode)
	}
	if gotUserID != user.ID {
		t.Errorf("ctxUserID = %v, want %v", gotUserID, user.ID)
	}
}

func TestRequireAuthenticated_JWT_Expired_401(t *testing.T) {
	t.Parallel()
	secret := []byte("testsecret")
	userID := uuid.New()
	// Issue token with TTL in the past — already expired when parsed.
	token, _ := auth.IssueAccessToken(secret, userID, 1, -1*time.Minute)

	srv := newAuthTestServer(t, "testsecret", nil)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired JWT: got %d, want 401", resp.StatusCode)
	}
}

func TestRequireAuthenticated_APIKey_Valid(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "APIKeyAuthOrg")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	user, err := db.CreateUser(ctx, "apikeyauth@example.com", "APIKeyAuthUser", "", 0)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	if _, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "test-key", "member", sql.NullTime{}); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var gotUserID uuid.UUID
	var gotAPIKeyRole string
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = r.Context().Value(ctxUserID).(uuid.UUID)
		gotAPIKeyRole, _ = r.Context().Value(ctxAPIKeyRole).(string)
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid API key: got %d, want 200", resp.StatusCode)
	}
	if gotUserID != user.ID {
		t.Errorf("ctxUserID = %v, want %v", gotUserID, user.ID)
	}
	if gotAPIKeyRole != "member" {
		t.Errorf("ctxAPIKeyRole = %q, want %q", gotAPIKeyRole, "member")
	}
}

func TestRequireAuthenticated_APIKey_Invalid_401(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	srv := newAuthTestServer(t, "testsecret", db)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	req.Header.Set("Authorization", "Bearer cvo_invalid_key_that_does_not_exist")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("invalid API key: got %d, want 401", resp.StatusCode)
	}
}

// TestRequireAuthenticated_AuthHeaderNoBearerPrefix verifies that an
// Authorization header without the "Bearer " prefix falls through to the
// cookie path and returns 401 when no cookie is present.
func TestRequireAuthenticated_AuthHeaderNoBearerPrefix(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer(t, "testsecret", nil)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("non-Bearer auth header without cookie: got %d, want 401", resp.StatusCode)
	}
}

// TestRequireAuthenticated_MalformedJWT_401 verifies that a malformed JWT
// cookie value (not a valid JWT at all) returns 401.
func TestRequireAuthenticated_MalformedJWT_401(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer(t, "testsecret", nil)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "not-a-valid-jwt"})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("malformed JWT cookie: got %d, want 401", resp.StatusCode)
	}
}

// TestRequireAuthenticated_JWT_WrongSecret_401 verifies that a JWT signed
// with a different secret is rejected.
func TestRequireAuthenticated_JWT_WrongSecret_401(t *testing.T) {
	t.Parallel()
	userID := uuid.New()
	// Sign with a different secret than the server uses.
	token, err := auth.IssueAccessToken([]byte("wrong-secret"), userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", nil)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("JWT signed with wrong secret: got %d, want 401", resp.StatusCode)
	}
}

// TestRequireAuthenticated_APIKey_ContextValues verifies that a valid API key
// request sets ctxUserID, ctxAPIKeyRole, and ctxAPIKeyOrgID correctly in the context.
func TestRequireAuthenticated_APIKey_ContextValues(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "APIKeyCtxOrg")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	user, err := db.CreateUser(ctx, "apikeyctx@example.com", "APIKeyCtxUser", "", 0)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "admin"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	if _, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "ctx-key", "admin", sql.NullTime{}); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var gotUserID uuid.UUID
	var gotAPIKeyRole string
	var gotAPIKeyOrgID uuid.UUID
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = r.Context().Value(ctxUserID).(uuid.UUID)
		gotAPIKeyRole, _ = r.Context().Value(ctxAPIKeyRole).(string)
		gotAPIKeyOrgID, _ = r.Context().Value(ctxAPIKeyOrgID).(uuid.UUID)
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid API key: got %d, want 200", resp.StatusCode)
	}
	if gotUserID != user.ID {
		t.Errorf("ctxUserID = %v, want %v", gotUserID, user.ID)
	}
	if gotAPIKeyRole != "admin" {
		t.Errorf("ctxAPIKeyRole = %q, want %q", gotAPIKeyRole, "admin")
	}
	if gotAPIKeyOrgID != org.ID {
		t.Errorf("ctxAPIKeyOrgID = %v, want %v", gotAPIKeyOrgID, org.ID)
	}
}

// TestRequireAuthenticated_ForcePasswordReset_BlocksNonAuthEndpoints verifies that
// a user with force_password_reset=true gets 403 on non-auth endpoints.
func TestRequireAuthenticated_ForcePasswordReset_BlocksNonAuthEndpoints(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "forcereset-block@example.com", "ForceResetBlock", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	secret := []byte("testsecret")
	token, err := auth.IssueAccessToken(secret, user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use httptest.NewRecorder to control the request URL path.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/orgs/some-org/cves", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("force_password_reset on non-auth endpoint: got %d, want 403", rec.Code)
	}

	// Verify the response body contains the expected error type.
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["type"] != "password_change_required" {
		t.Errorf("error type = %q, want %q", body["type"], "password_change_required")
	}
}

// TestRequireAuthenticated_ForcePasswordReset_AllowsChangePassword verifies that
// a user with force_password_reset=true can still access /auth/change-password.
func TestRequireAuthenticated_ForcePasswordReset_AllowsChangePassword(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "forcereset-cp@example.com", "ForceResetCP", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	secret := []byte("testsecret")
	token, err := auth.IssueAccessToken(secret, user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var reached bool
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/change-password", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("force_password_reset on /auth/change-password: got %d, want 200", rec.Code)
	}
	if !reached {
		t.Error("handler was not reached — middleware blocked /auth/change-password")
	}
}

// TestRequireAuthenticated_ForcePasswordReset_AllowsMe verifies that
// a user with force_password_reset=true can still access /auth/me.
func TestRequireAuthenticated_ForcePasswordReset_AllowsMe(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "forcereset-me@example.com", "ForceResetMe", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	secret := []byte("testsecret")
	token, err := auth.IssueAccessToken(secret, user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var reached bool
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("force_password_reset on /auth/me: got %d, want 200", rec.Code)
	}
	if !reached {
		t.Error("handler was not reached — middleware blocked /auth/me")
	}
}

// TestRequireAuthenticated_ForcePasswordReset_AllowsMFARoutes verifies that
// a user with force_password_reset=true can access /auth/mfa/* routes.
func TestRequireAuthenticated_ForcePasswordReset_AllowsMFARoutes(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "forcereset-mfa@example.com", "ForceResetMFA", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := db.AdminForcePasswordReset(ctx, user.ID); err != nil {
		t.Fatalf("set force_password_reset: %v", err)
	}

	secret := []byte("testsecret")
	token, err := auth.IssueAccessToken(secret, user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, "testsecret", db)
	var reached bool
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/methods", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("force_password_reset on /auth/mfa/methods: got %d, want 200", rec.Code)
	}
	if !reached {
		t.Error("handler was not reached — middleware blocked /auth/mfa/methods")
	}
}

// TestRequireAuthenticated_ReadsFromConfigHolder verifies that JWT parsing reads
// from the hot-reloadable configHolder, not from the static startup config.
func TestRequireAuthenticated_ReadsFromConfigHolder(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "hotreload@example.com", "HotReload", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// Server starts with JWTSecret="original-secret-at-startup".
	originalSecret := "original-secret-at-startup!!!!!"
	newSecret := "rotated-secret-after-reload!!!!!"

	// Seed the configHolder with the original secret.
	holder := config.NewHolder(&config.ReloadableConfig{
		JWTSecret: []byte(originalSecret),
	})
	cfg := &config.Config{JWTSecret: originalSecret} //nolint:exhaustruct // test: only JWT secret needed
	srv, _ := NewServer(db.Store, cfg, ServerDeps{ConfigHolder: holder})
	t.Cleanup(srv.Close)

	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Issue a token with the NEW secret (not yet known to the server).
	token, err := auth.IssueAccessToken([]byte(newSecret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	// Request with the new-secret token BEFORE reload → should fail.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("before reload: got %d, want 401", rec.Code)
	}

	// Hot-reload: update configHolder with the new secret.
	holder.Store(&config.ReloadableConfig{
		JWTSecret: []byte(newSecret),
	})

	// Same token AFTER reload → should succeed.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("after reload: got %d, want 200", rec.Code)
	}
}
