// ABOUTME: Tests for RequireSiteAdmin middleware — non-admin and API keys get 403, admin session gets 200.
// ABOUTME: Uses real Postgres via testutil.NewTestDB for accurate integration testing.
package api

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRequireSiteAdmin_NonAdmin_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a regular user (not site admin).
	user, err := db.CreateUser(ctx, "nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "testsecret"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	handler := srv.RequireAuthenticated()(srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.AddCookie(requestCookie("access_token", token))
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin user: got %d, want 403", resp.StatusCode)
	}
	assertRFC9457Response(t, resp, http.StatusForbidden)
}

func TestRequireSiteAdmin_Admin_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a user and promote to site admin.
	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "testsecret"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	handler := srv.RequireAuthenticated()(srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	req.AddCookie(requestCookie("access_token", token))
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("site admin user: got %d, want 200", resp.StatusCode)
	}
}

// createSiteAdminAPIKey creates a site-admin user who owns an org, plus an API key
// with the given role in that org. Returns the user, the raw key, and the org ID.
func createSiteAdminAPIKey(t *testing.T, db *testutil.TestDB, role string) (uuid.UUID, string, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	user, err := db.CreateUser(ctx, "siteadmin-key@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}
	org, err := db.CreateOrg(ctx, "SiteAdminKeyOrg")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "owner"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	rawKey, keyHash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	if _, err := db.CreateAPIKey(ctx, org.ID, user.ID, keyHash, "site-admin-key", role, sql.NullTime{}); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	return user.ID, rawKey, org.ID
}

// TestRequireSiteAdmin_APIKey_403 verifies that an API key never carries its
// creator's site-admin power, whatever the key's role.
func TestRequireSiteAdmin_APIKey_403(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"viewer", "member", "admin"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			db := testutil.NewTestDB(t)
			_, rawKey, _ := createSiteAdminAPIKey(t, db, role)

			srv := newAuthTestServer(t, "testsecret", db)
			handler := srv.RequireAuthenticated()(srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})))
			ts := httptest.NewServer(handler)
			t.Cleanup(ts.Close)

			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
			req.Header.Set("Authorization", "Bearer "+rawKey)
			resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close() //nolint:errcheck
			assertRFC9457Response(t, resp, http.StatusForbidden)
		})
	}
}

// TestAdminRoutes_APIKey_403 verifies that every /api/v1/admin route refuses an
// API key created by a site admin, while the same user's session cookie passes.
func TestAdminRoutes_APIKey_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	userID, rawKey, orgID := createSiteAdminAPIKey(t, db, "admin")

	secret := "test-jwt-secret-admin-routes-key"
	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	id := uuid.New().String()
	routes := []struct{ method, path string }{
		{http.MethodGet, "/feeds"},
		{http.MethodPost, "/feeds/nvd/run"},
		{http.MethodPost, "/feeds/nvd/pause"},
		{http.MethodPost, "/feeds/nvd/resume"},
		{http.MethodGet, "/feeds/nvd/logs"},
		{http.MethodGet, "/version"},
		{http.MethodGet, "/doctor"},
		{http.MethodGet, "/orgs"},
		{http.MethodPatch, "/orgs/" + orgID.String()},
		{http.MethodGet, "/orgs/" + orgID.String() + "/usage"},
		{http.MethodGet, "/users"},
		{http.MethodPost, "/users/" + id + "/disable"},
		{http.MethodPost, "/users/" + id + "/enable"},
		{http.MethodPost, "/users/" + id + "/unlock"},
		{http.MethodPost, "/users/" + id + "/reset-password"},
		{http.MethodGet, "/deliveries"},
		{http.MethodPost, "/deliveries/" + id + "/retry"},
		{http.MethodPost, "/deliveries/retry-failed"},
		{http.MethodPost, "/reindex"},
		{http.MethodPost, "/reload-config"},
		{http.MethodGet, "/config"},
		{http.MethodGet, "/audit-log"},
		{http.MethodGet, "/security-events"},
	}
	for _, rt := range routes {
		req, _ := http.NewRequestWithContext(ctx, rt.method, ts.URL+"/api/v1/admin"+rt.path, bytes.NewBufferString(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+rawKey)
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
		if err != nil {
			t.Fatalf("%s %s: %v", rt.method, rt.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s with API key: got %d, want 403", rt.method, rt.path, resp.StatusCode)
		}
	}

	// Positive control: the same site admin's session cookie reaches the handler.
	token, err := auth.IssueAccessToken([]byte(secret), userID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/orgs", nil)
	req.AddCookie(requestCookie("access_token", token))
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("cookie request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /admin/orgs with session cookie: got %d, want 200", resp.StatusCode)
	}
}

func TestRequireSiteAdmin_NoAuth_401(t *testing.T) {
	t.Parallel()
	srv := newAuthTestServer(t, "testsecret", nil)
	// RequireSiteAdmin without RequireAuthenticated — should get 401 because no userID in context.
	handler := srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth context: got %d, want 401", resp.StatusCode)
	}
}

func TestRequireSiteAdmin_UnknownUser_500(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)

	// Capture expected error log to keep test output pristine.
	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

	fakeUserID := uuid.New()

	srv := newAuthTestServer(t, "testsecret", db)
	// Manually inject ctxUserID with a non-existent user, then RequireSiteAdmin.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxUserID, fakeUserID)
		srv.RequireSiteAdmin()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r.WithContext(ctx))
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL, nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	// Unknown user ID → IsSiteAdmin returns sql.ErrNoRows → 500.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("unknown user: got %d, want 500", resp.StatusCode)
	}
	if !strings.Contains(buf.String(), "check site admin") {
		t.Errorf("expected 'check site admin' in log output, got: %s", buf.String())
	}
}
