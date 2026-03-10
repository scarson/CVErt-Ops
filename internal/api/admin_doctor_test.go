// ABOUTME: Tests for GET /api/v1/admin/doctor endpoint.
// ABOUTME: Verifies site admin auth and JSON check results structure.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/doctor"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAdminDoctor_Unauthenticated_401(t *testing.T) {
	t.Parallel()

	srv := newAuthTestServer(t, "test-jwt-secret-for-admin-doctor!!", nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/admin/doctor", nil)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated: got %d, want 401", resp.StatusCode)
	}
}

func TestAdminDoctor_NonAdmin_403(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "nonadmin@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "test-jwt-secret-for-admin-doctor!!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/doctor", nil)
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

func TestAdminDoctor_SiteAdmin_ReturnsChecks(t *testing.T) {
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

	secret := "test-jwt-secret-for-admin-doctor!!"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/doctor", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Accept either 200 (all pass) or 503 (some fail) — test DB may not have
	// all RLS policies, migrations, etc. The point is the endpoint works.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 200 or 503", resp.StatusCode)
	}

	var body struct {
		Status string          `json:"status"`
		Checks []doctor.Result `json:"checks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Checks) == 0 {
		t.Error("expected at least one check result")
	}
}
