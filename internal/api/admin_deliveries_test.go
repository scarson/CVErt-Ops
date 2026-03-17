// ABOUTME: Tests for admin bulk retry deliveries endpoint.
// ABOUTME: Verifies limit comes exclusively from query param, ignoring JSON body.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestBulkRetryDeliveries_IgnoresBodyLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create admin user.
	admin, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-admin-deliveries"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// POST with query param limit=50 and body limit=0 (invalid for body validation).
	// The body should be ignored entirely; handler should succeed (200).
	body := `{"limit": 0}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/deliveries/retry-failed?limit=50",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if result["status"] != "retried" {
		t.Errorf("status = %v, want %q", result["status"], "retried")
	}
}

func TestBulkRetryDeliveries_DefaultLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create admin user.
	admin, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-admin-deliveries-default"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// POST without query param or body — should use default limit (100).
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/admin/deliveries/retry-failed",
		nil)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if result["status"] != "retried" {
		t.Errorf("status = %v, want %q", result["status"], "retried")
	}
	// Fresh test DB has no failed deliveries, so rows_affected should be 0.
	if result["rows_affected"] != float64(0) {
		t.Errorf("rows_affected = %v, want 0", result["rows_affected"])
	}
}
