// ABOUTME: Tests for the admin security events listing endpoint.
// ABOUTME: Verifies auth gating, filtering, pagination, and empty results.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestAdminSecurityEvents_RequiresSiteAdmin(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a regular (non-admin) user.
	user, err := db.CreateUser(ctx, "regular@example.com", "Regular", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	secret := "test-jwt-secret-sec-events-auth"
	token, err := auth.IssueAccessToken([]byte(secret), user.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/admin/security-events", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
}

// secEventsTestEnv holds the shared test environment for security events tests.
type secEventsTestEnv struct {
	db    *testutil.TestDB
	ts    *httptest.Server
	token string
}

func setupSecurityEventsTest(t *testing.T) secEventsTestEnv {
	t.Helper()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	admin, err := db.CreateUser(ctx, "admin@example.com", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}

	secret := "test-jwt-secret-sec-events"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	return secEventsTestEnv{db: db, ts: ts, token: token}
}

// doGet creates and executes a GET request with the admin cookie attached.
func (env secEventsTestEnv) doGet(t *testing.T, url string) *http.Response {
	t.Helper()
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: env.token})
	resp, err := env.ts.Client().Do(req) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("request %s: %v", url, err)
	}
	return resp
}

func TestAdminSecurityEvents_ReturnsEvents(t *testing.T) {
	t.Parallel()
	env := setupSecurityEventsTest(t)
	ctx := context.Background()

	// Insert test events.
	for _, ev := range []store.InsertSecurityEventParams{
		{EventType: "login_failed", Severity: "warning", ActorEmail: "user1@example.com"},
		{EventType: "login_success", Severity: "info", ActorEmail: "user2@example.com"},
		{EventType: "login_failed", Severity: "critical", ActorEmail: "user3@example.com"},
	} {
		if err := env.db.InsertSecurityEvent(ctx, ev); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	resp := env.doGet(t, env.ts.URL+"/api/v1/admin/security-events")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var result struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(result.Items) != 3 {
		t.Fatalf("got %d items, want 3", len(result.Items))
	}
}

func TestAdminSecurityEvents_FilterByType(t *testing.T) {
	t.Parallel()
	env := setupSecurityEventsTest(t)
	ctx := context.Background()

	for _, ev := range []store.InsertSecurityEventParams{
		{EventType: "login_failed", Severity: "warning", ActorEmail: "user1@example.com"},
		{EventType: "login_success", Severity: "info", ActorEmail: "user2@example.com"},
		{EventType: "login_failed", Severity: "critical", ActorEmail: "user3@example.com"},
	} {
		if err := env.db.InsertSecurityEvent(ctx, ev); err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}

	resp := env.doGet(t, env.ts.URL+"/api/v1/admin/security-events?event_type=login_failed")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var result struct {
		Items []struct {
			EventType string `json:"event_type"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(result.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(result.Items))
	}
	for _, item := range result.Items {
		if item.EventType != "login_failed" {
			t.Errorf("got event_type %q, want login_failed", item.EventType)
		}
	}
}

func TestAdminSecurityEvents_Pagination(t *testing.T) {
	t.Parallel()
	env := setupSecurityEventsTest(t)
	ctx := context.Background()

	// Insert 3 events with staggered times to ensure deterministic ordering.
	for i := range 3 {
		if err := env.db.InsertSecurityEvent(ctx, store.InsertSecurityEventParams{
			EventType:  "test_event",
			Severity:   "info",
			ActorEmail: "pager@example.com",
		}); err != nil {
			t.Fatalf("insert event %d: %v", i, err)
		}
		// Small sleep to ensure distinct created_at timestamps.
		time.Sleep(5 * time.Millisecond)
	}

	// Page 1: limit=2.
	resp := env.doGet(t, env.ts.URL+"/api/v1/admin/security-events?limit=2")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("page 1: got %d, want 200", resp.StatusCode)
	}

	var page1 struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page1); err != nil {
		t.Fatalf("page 1 decode: %v", err)
	}

	if len(page1.Items) != 2 {
		t.Fatalf("page 1: got %d items, want 2", len(page1.Items))
	}
	if page1.NextCursor == "" {
		t.Fatal("page 1: expected non-empty next_cursor")
	}

	// Page 2: use cursor.
	resp2 := env.doGet(t, env.ts.URL+"/api/v1/admin/security-events?limit=2&cursor="+page1.NextCursor)
	defer resp2.Body.Close() //nolint:errcheck

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("page 2: got %d, want 200", resp2.StatusCode)
	}

	var page2 struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&page2); err != nil {
		t.Fatalf("page 2 decode: %v", err)
	}

	if len(page2.Items) != 1 {
		t.Fatalf("page 2: got %d items, want 1", len(page2.Items))
	}
	if page2.NextCursor != "" {
		t.Errorf("page 2: expected empty next_cursor, got %q", page2.NextCursor)
	}
}

func TestAdminSecurityEvents_EmptyResult(t *testing.T) {
	t.Parallel()
	env := setupSecurityEventsTest(t)

	resp := env.doGet(t, env.ts.URL+"/api/v1/admin/security-events")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d, want 200", resp.StatusCode)
	}

	var result struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(result.Items) != 0 {
		t.Fatalf("got %d items, want 0", len(result.Items))
	}
	if result.NextCursor != "" {
		t.Errorf("expected empty next_cursor, got %q", result.NextCursor)
	}
}
