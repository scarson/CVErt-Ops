// ABOUTME: Tests for the inbound webhook endpoint (POST /api/v1/orgs/{org_id}/ingest).
// ABOUTME: Covers CVE ID validation, reserved names, patch limits, rate accounting, and merge integration.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newIngestTestServer creates a Server + httptest.Server for ingest handler tests.
// Registers a user, logs in, and returns the access token and org ID.
func newIngestTestServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server, string, string) {
	t.Helper()
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Register and login.
	reg := doRegister(t, ctx, ts, "ingest-user@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ingest-user@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	return nil, ts, token, reg.OrgID
}

func doIngest(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/ingest",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704: test framework URL
	if err != nil {
		t.Fatalf("ingest request: %v", err)
	}
	return resp
}

func TestIngestHandler_AcceptsValidPatches(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"my-scanner","patches":[
		{"cve_id":"CVE-2026-0001","description":"Test vulnerability"}
	]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}

	var result ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Accepted != 1 {
		t.Errorf("accepted: want 1, got %d", result.Accepted)
	}
	if result.Rejected != 0 {
		t.Errorf("rejected: want 0, got %d", result.Rejected)
	}
}

func TestIngestHandler_RejectsReservedSourceName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"nvd","patches":[{"cve_id":"CVE-2026-0001"}]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", resp.StatusCode)
	}
}

func TestIngestHandler_PartialFailure(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"scanner","patches":[
		{"cve_id":"CVE-2026-0001","description":"Valid"},
		{"cve_id":"INVALID","description":"Bad ID"}
	]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202 (partial), got %d", resp.StatusCode)
	}

	var result ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Accepted != 1 {
		t.Errorf("accepted: want 1, got %d", result.Accepted)
	}
	if result.Rejected != 1 {
		t.Errorf("rejected: want 1, got %d", result.Rejected)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors: want 1, got %d", len(result.Errors))
	}
	if result.Errors[0].Index != 1 {
		t.Errorf("error index: want 1, got %d", result.Errors[0].Index)
	}
}

func TestIngestHandler_AllPatchesInvalid(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"scanner","patches":[
		{"cve_id":"INVALID-1"},
		{"cve_id":"ALSO-INVALID"}
	]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("want 400 (all rejected), got %d", resp.StatusCode)
	}

	var result ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Accepted != 0 {
		t.Errorf("accepted: want 0, got %d", result.Accepted)
	}
	if result.Rejected != 2 {
		t.Errorf("rejected: want 2, got %d", result.Rejected)
	}
}

func TestIngestHandler_ExceedsPatchLimit(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	// Build a request with 101 patches.
	var patches []string
	for i := 0; i <= maxIngestPatches; i++ {
		patches = append(patches, fmt.Sprintf(`{"cve_id":"CVE-2026-%04d"}`, i+1000))
	}
	body := fmt.Sprintf(`{"source_name":"scanner","patches":[%s]}`, strings.Join(patches, ","))

	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", resp.StatusCode)
	}
}

func TestIngestHandler_CVEIDValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	tests := []struct {
		cveID string
		valid bool
	}{
		{"CVE-2026-1234", true},
		{"CVE-2026-12345", true},
		{"CVE-1999-0001", true},
		{"CVE-2026-123", false},  // too few digits in sequence
		{"cve-2026-1234", false}, // lowercase
		{"CVE-2026", false},      // no sequence
		{"GHSA-1234-abcd", false},
		{"", false},
	}

	for _, tc := range tests {
		body := fmt.Sprintf(`{"source_name":"scanner","patches":[{"cve_id":%q}]}`, tc.cveID)
		resp := doIngest(t, ctx, ts, token, orgID, body)

		var result ingestResponse
		_ = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close() //nolint:errcheck,gosec

		if tc.valid && result.Accepted != 1 {
			t.Errorf("CVE ID %q: expected accepted, got rejected", tc.cveID)
		}
		if !tc.valid && result.Rejected != 1 {
			t.Errorf("CVE ID %q: expected rejected, got accepted", tc.cveID)
		}
	}
}

func TestIngestHandler_EmptySourceName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"","patches":[{"cve_id":"CVE-2026-1234"}]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", resp.StatusCode)
	}
}

func TestIngestHandler_EmptyPatchesArray(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	body := `{"source_name":"scanner","patches":[]}`
	resp := doIngest(t, ctx, ts, token, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d", resp.StatusCode)
	}
}

func TestIngestHandler_RateLimitCountsAsNRequests(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a server with very low rate limit config for testing.
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive on test config
		JWTSecret:           "ingest-test-secret",
		RegistrationMode:    "open",
		Argon2MaxConcurrent: 5,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)

	reg := doRegister(t, ctx, ts, "ratelimit@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ratelimit@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// The default free-tier rate is 60/min (burst ~10). Send many requests
	// to exhaust the rate limit. This verifies N-patch requests consume N tokens.
	// First, exhaust the burst by sending multiple small requests.
	for i := 0; i < 12; i++ {
		body := `{"source_name":"scanner","patches":[{"cve_id":"CVE-2026-1234"}]}`
		resp := doIngest(t, ctx, ts, token, reg.OrgID, body)
		resp.Body.Close() //nolint:errcheck,gosec
	}

	// Now a request with multiple patches should be rate limited because
	// the burst is exhausted.
	var patches []string
	for i := 0; i < 5; i++ {
		patches = append(patches, fmt.Sprintf(`{"cve_id":"CVE-2026-%04d"}`, i+2000))
	}
	body := fmt.Sprintf(`{"source_name":"scanner","patches":[%s]}`, strings.Join(patches, ","))
	resp := doIngest(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("want 429 (rate limited), got %d", resp.StatusCode)
	}
}

func TestIngestHandler_ViewerDenied(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, token, orgID := newIngestTestServer(t, db)

	// Invite a viewer.
	viewerToken := inviteAndLogin(t, ctx, db, ts, token, orgID, "viewer@example.com", "viewer")

	body := `{"source_name":"scanner","patches":[{"cve_id":"CVE-2026-1234"}]}`
	resp := doIngest(t, ctx, ts, viewerToken, orgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 (viewer denied), got %d", resp.StatusCode)
	}
}

func TestIngestHandler_Unauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts, _, orgID := newIngestTestServer(t, db)

	// Request with no auth.
	body := `{"source_name":"scanner","patches":[{"cve_id":"CVE-2026-1234"}]}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+orgID+"/ingest",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704: test framework URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

func TestCrossOrg_IngestAccess(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice owns org A.
	aliceReg := doRegister(t, ctx, ts, "alice-ingest@example.com", "test-password-1234")

	// Bob owns org B, tries to ingest to Alice's org.
	doRegister(t, ctx, ts, "bob-ingest@example.com", "test-password-1234")
	bobLoginResp := doLogin(t, ctx, ts, "bob-ingest@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLoginResp, "access_token")

	body := `{"source_name":"custom","patches":[{"cve_id":"CVE-2025-9999","status":"published"}]}`
	resp := doIngest(t, ctx, ts, bobToken, aliceReg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org ingest: got %d, want 403", resp.StatusCode)
	}
}
