// ABOUTME: Tests for admin org list and patch endpoints.
// ABOUTME: Verifies atomic PATCH and consistent response shapes between list and patch.
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

func TestAdminPatchOrg_AtomicTierAndSuspend(t *testing.T) {
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

	// Create an org to patch.
	org, err := db.CreateOrg(ctx, "Test Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	secret := "test-jwt-secret-admin-orgs"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// PATCH with both tier and suspend in a single request.
	body := `{"tier":"pro","suspend":true}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
		ts.URL+"/api/v1/admin/orgs/"+org.ID.String(),
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

	// Verify both tier and suspend applied atomically.
	if result["tier"] != "pro" {
		t.Errorf("tier = %v, want %q", result["tier"], "pro")
	}
	if result["suspended_at"] == nil {
		t.Error("suspended_at should be set after suspend=true")
	}

	// Verify response includes member_count and last_activity_at fields.
	if _, ok := result["member_count"]; !ok {
		t.Error("response missing member_count field")
	}
	if _, ok := result["last_activity_at"]; !ok {
		t.Error("response missing last_activity_at field (should be present even if null)")
	}
}

func TestAdminListOrgs_ResponseShape_MatchesPatch(t *testing.T) {
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

	// Create an org.
	org, err := db.CreateOrg(ctx, "Shape Test Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	secret := "test-jwt-secret-admin-orgs-shape"
	token, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// GET /admin/orgs — capture response field keys from first item.
	listReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/admin/orgs", nil)
	listReq.AddCookie(&http.Cookie{Name: "access_token", Value: token})
	listResp, err := ts.Client().Do(listReq) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close() //nolint:errcheck

	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listResp.StatusCode)
	}

	var listBody struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listBody); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listBody.Items) == 0 {
		t.Fatal("list returned 0 items")
	}

	listKeys := make(map[string]bool)
	for k := range listBody.Items[0] {
		listKeys[k] = true
	}

	// PATCH /admin/orgs/{id} — capture response field keys.
	patchBody := `{"tier":"pro"}`
	patchReq, _ := http.NewRequestWithContext(ctx, http.MethodPatch,
		ts.URL+"/api/v1/admin/orgs/"+org.ID.String(),
		bytes.NewBufferString(patchBody))
	patchReq.Header.Set("Content-Type", "application/json")
	patchReq.Header.Set("X-Requested-By", "CVErt-Ops")
	patchReq.AddCookie(&http.Cookie{Name: "access_token", Value: token})

	patchResp, err := ts.Client().Do(patchReq) //nolint:gosec // G704 false positive: test server URL
	if err != nil {
		t.Fatalf("patch request: %v", err)
	}
	defer patchResp.Body.Close() //nolint:errcheck

	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch: got %d, want 200", patchResp.StatusCode)
	}

	var patchResult map[string]any
	if err := json.NewDecoder(patchResp.Body).Decode(&patchResult); err != nil {
		t.Fatalf("decode patch: %v", err)
	}

	patchKeys := make(map[string]bool)
	for k := range patchResult {
		patchKeys[k] = true
	}

	// Assert same keys in both responses.
	for k := range listKeys {
		if !patchKeys[k] {
			t.Errorf("list has key %q but patch response does not", k)
		}
	}
	for k := range patchKeys {
		if !listKeys[k] {
			t.Errorf("patch has key %q but list response does not", k)
		}
	}
}
