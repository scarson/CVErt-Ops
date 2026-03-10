// ABOUTME: Tests for GET /api/v1/admin/version endpoint.
// ABOUTME: Verifies site admin auth, version fields present, and non-admin rejection.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAdminVersion_SiteAdmin_200(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, user.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-for-admin-version"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	srv.SetVersionInfo(VersionInfo{
		Version:   "1.0.0",
		Commit:    "abc123",
		BuildTime: "2026-03-10T00:00:00Z",
	})
	handler := srv.Handler()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/version", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var body struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
		GoVersion string `json:"go_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Version != "1.0.0" {
		t.Errorf("version = %q, want %q", body.Version, "1.0.0")
	}
	if body.Commit != "abc123" {
		t.Errorf("commit = %q, want %q", body.Commit, "abc123")
	}
	if body.GoVersion == "" {
		t.Error("go_version should not be empty")
	}
}

func TestAdminVersion_NonAdmin_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "test-jwt-secret-for-admin-version"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/version", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin: got %d, want 403", resp.StatusCode)
	}
}

func TestAdminVersion_Unauthenticated_401(t *testing.T) {
	t.Parallel()

	srv := newAuthTestServer(t, "test-jwt-secret-for-admin-version", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/admin/version", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got %d, want 401", resp.StatusCode)
	}
}
