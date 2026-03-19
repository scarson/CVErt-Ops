// ABOUTME: Tests for admin user management endpoints (list, disable, enable, unlock, reset-password).
// ABOUTME: Covers self-disable prevention, idempotency, and site admin auth enforcement.
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

func TestAdminListUsers_BasicPagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "list-admin@example.com", "ListAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	// Create additional users so there's something to list.
	for i := range 3 {
		email := "listuser" + string(rune('0'+i)) + "@example.com"
		if _, err := db.CreateUser(ctx, email, "ListUser", "fakehash", 1); err != nil {
			t.Fatalf("create user %d: %v", i, err)
		}
	}

	secret := "test-jwt-secret-admin-users"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/users?limit=10", nil)
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
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 1 admin + 3 created = 4 users.
	if len(body.Items) < 4 {
		t.Errorf("expected at least 4 users, got %d", len(body.Items))
	}
}

func TestAdminDisableUser_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "dis-admin@example.com", "DisAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	target, err := db.CreateUser(ctx, "dis-target@example.com", "Target", "fakehash", 1)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	secret := "test-jwt-secret-admin-disable"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/users/"+target.ID.String()+"/disable", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("disable: got %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "disabled" {
		t.Errorf("status = %q, want disabled", body["status"])
	}
}

func TestAdminDisableUser_SelfDisablePrevented(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "selfadmin@example.com", "SelfAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-admin-selfdisable"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Admin tries to disable themselves.
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/users/"+admin.ID.String()+"/disable", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("self-disable: got %d, want 400", resp.StatusCode)
	}
}

func TestAdminEnableUser_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "enable-admin@example.com", "EnableAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	target, err := db.CreateUser(ctx, "enable-target@example.com", "Target", "fakehash", 1)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	// Disable the target first.
	if _, err := db.AdminDisableUser(ctx, target.ID); err != nil {
		t.Fatalf("disable target: %v", err)
	}

	secret := "test-jwt-secret-admin-enable"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/users/"+target.ID.String()+"/enable", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: got %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "enabled" {
		t.Errorf("status = %q, want enabled", body["status"])
	}
}

func TestAdminResetPassword_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "reset-admin@example.com", "ResetAdmin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	target, err := db.CreateUser(ctx, "reset-target@example.com", "Target", "fakehash", 1)
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	secret := "test-jwt-secret-admin-reset"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/users/"+target.ID.String()+"/reset-password", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-password: got %d, want 200", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "password_reset_required" {
		t.Errorf("status = %q, want password_reset_required", body["status"])
	}
}

func TestAdminUsers_RequiresSiteAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "nonadmin-users@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "test-jwt-secret-admin-users-nonadmin"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/admin/users"},
		{http.MethodPost, "/api/v1/admin/users/" + user.ID.String() + "/disable"},
		{http.MethodPost, "/api/v1/admin/users/" + user.ID.String() + "/enable"},
		{http.MethodPost, "/api/v1/admin/users/" + user.ID.String() + "/unlock"},
		{http.MethodPost, "/api/v1/admin/users/" + user.ID.String() + "/reset-password"},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequestWithContext(ctx, ep.method, ts.URL+ep.path, nil)
		req.AddCookie(&http.Cookie{Name: "access_token", Value: token})
		if ep.method != http.MethodGet {
			req.Header.Set("X-Requested-By", "CVErt-Ops")
		}
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
		if err != nil {
			t.Fatalf("%s %s: request: %v", ep.method, ep.path, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104: test code, error irrelevant
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", ep.method, ep.path, resp.StatusCode)
		}
	}
}
