// ABOUTME: Tests for RequireAuthenticated middleware (JWT cookie + API key Bearer).
// ABOUTME: Uses package api to access unexported context keys and Server fields.
package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

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
