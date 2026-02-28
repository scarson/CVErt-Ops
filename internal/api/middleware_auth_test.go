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
func newAuthTestServer(jwtSecret string, db *testutil.TestDB) *Server {
	cfg := &config.Config{JWTSecret: jwtSecret} //nolint:exhaustruct // test: only JWT secret needed
	var srv *Server
	if db != nil {
		srv, _ = NewServer(db.Store, cfg)
	} else {
		srv, _ = NewServer(nil, cfg)
	}
	return srv
}

func TestRequireAuthenticated_NoCredentials_401(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer("testsecret", nil)
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
	secret := []byte("testsecret")
	userID := uuid.New()
	token, err := auth.IssueAccessToken(secret, userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer("testsecret", nil)
	var gotUserID uuid.UUID
	handler := srv.RequireAuthenticated()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserID, _ = r.Context().Value(ctxUserID).(uuid.UUID)
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
	if resp.StatusCode != http.StatusOK {
		t.Errorf("valid JWT: got %d, want 200", resp.StatusCode)
	}
	if gotUserID != userID {
		t.Errorf("ctxUserID = %v, want %v", gotUserID, userID)
	}
}

func TestRequireAuthenticated_JWT_Expired_401(t *testing.T) {
	t.Parallel()
	secret := []byte("testsecret")
	userID := uuid.New()
	// Issue token with TTL in the past — already expired when parsed.
	token, _ := auth.IssueAccessToken(secret, userID, 1, -1*time.Minute)

	srv := newAuthTestServer("testsecret", nil)
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

	srv := newAuthTestServer("testsecret", db)
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

	srv := newAuthTestServer("testsecret", db)
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
