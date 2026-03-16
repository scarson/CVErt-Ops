// ABOUTME: Integration tests for saved search CRUD and execute handlers.
// ABOUTME: Tests RBAC, private visibility, validation, soft-delete, and DSL execution.
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
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newSavedSearchTestServer creates a Server for saved search handler tests.
func newSavedSearchTestServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "sstestsecret",
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
	return srv, ts
}

// doCreateSavedSearch calls POST /api/v1/orgs/{orgID}/saved-searches.
func doCreateSavedSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/saved-searches", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create saved search request: %v", err)
	}
	return resp
}

// doListSavedSearches calls GET /api/v1/orgs/{orgID}/saved-searches.
func doListSavedSearches(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, visibility string) *http.Response {
	t.Helper()
	url := ts.URL + "/api/v1/orgs/" + orgID + "/saved-searches"
	if visibility != "" {
		url += "?visibility=" + visibility
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list saved searches request: %v", err)
	}
	return resp
}

// doGetSavedSearch calls GET /api/v1/orgs/{orgID}/saved-searches/{id}.
func doGetSavedSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/saved-searches/"+id, nil)
	req.Header.Set("Cookie", "access_token="+token)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get saved search request: %v", err)
	}
	return resp
}

// doPatchSavedSearch calls PATCH /api/v1/orgs/{orgID}/saved-searches/{id}.
func doPatchSavedSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/saved-searches/"+id, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("patch saved search request: %v", err)
	}
	return resp
}

// doDeleteSavedSearch calls DELETE /api/v1/orgs/{orgID}/saved-searches/{id}.
func doDeleteSavedSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/saved-searches/"+id, nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete saved search request: %v", err)
	}
	return resp
}

// doExecuteSavedSearch calls POST /api/v1/orgs/{orgID}/saved-searches/{id}/execute.
func doExecuteSavedSearch(t *testing.T, ctx context.Context, ts *httptest.Server, token, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/saved-searches/"+id+"/execute", nil)
	req.Header.Set("Cookie", "access_token="+token)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("execute saved search request: %v", err)
	}
	return resp
}

// validDSLJSON is a minimal valid DSL query for testing.
const validDSLJSON = `{"logic":"and","conditions":[{"field":"severity","operator":"in","value":["critical","high"]}]}`

// TestSavedSearch_CRUD tests the full create → get → list → patch → delete lifecycle.
func TestSavedSearch_CRUD(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-crud@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-crud@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// 1. Create
	body := fmt.Sprintf(`{"name":"My Search","query_json":%s,"is_shared":false}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		var errBody json.RawMessage
		json.NewDecoder(createResp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("create: got %d, want 201; body: %s", createResp.StatusCode, errBody)
	}

	var created savedSearchEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created search has empty id")
	}
	if created.Name != "My Search" {
		t.Errorf("name = %q, want %q", created.Name, "My Search")
	}
	if created.IsShared {
		t.Error("is_shared should be false")
	}

	// 2. Get
	getResp := doGetSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get: got %d, want 200", getResp.StatusCode)
	}
	var got savedSearchEntry
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get response: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("get id = %q, want %q", got.ID, created.ID)
	}

	// 3. List
	listResp := doListSavedSearches(t, ctx, ts, token, reg.OrgID, "")
	defer listResp.Body.Close() //nolint:errcheck,gosec
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", listResp.StatusCode)
	}
	var list listResponse[savedSearchEntry]
	if err := json.NewDecoder(listResp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("list len = %d, want 1", len(list.Items))
	}

	// 4. Patch
	patchBody := `{"name":"Updated Search","is_shared":true}`
	patchResp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID, patchBody)
	defer patchResp.Body.Close() //nolint:errcheck,gosec
	if patchResp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		json.NewDecoder(patchResp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("patch: got %d, want 200; body: %s", patchResp.StatusCode, errBody)
	}
	var patched savedSearchEntry
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch response: %v", err)
	}
	if patched.Name != "Updated Search" {
		t.Errorf("patched name = %q, want %q", patched.Name, "Updated Search")
	}
	if !patched.IsShared {
		t.Error("patched is_shared should be true")
	}

	// 5. Delete
	delResp := doDeleteSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204", delResp.StatusCode)
	}
}

// TestSavedSearch_CreateValidation tests validation: empty name → 400, invalid DSL → 422.
func TestSavedSearch_CreateValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-val@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-val@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Empty name → 422 (validation error, not malformed)
	body := fmt.Sprintf(`{"name":"","query_json":%s}`, validDSLJSON)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty name: got %d, want 422", resp.StatusCode)
	}

	// Invalid DSL → 422
	body2 := `{"name":"Bad DSL","query_json":{"logic":"nope","conditions":[]}}`
	resp2 := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body2)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid DSL: got %d, want 422", resp2.StatusCode)
	}
}

// TestSavedSearch_CreateValidation_NameLength tests that names exceeding 255 characters
// are rejected with 422.
func TestSavedSearch_CreateValidation_NameLength(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-namelen@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-namelen@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Exactly 255 characters should succeed.
	name255 := strings.Repeat("a", 255)
	body := fmt.Sprintf(`{"name":"%s","query_json":%s}`, name255, validDSLJSON)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("name 255 chars: got %d, want 201", resp.StatusCode)
	}

	// 256 characters should be rejected.
	name256 := strings.Repeat("a", 256)
	body2 := fmt.Sprintf(`{"name":"%s","query_json":%s}`, name256, validDSLJSON)
	resp2 := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body2)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("name 256 chars: got %d, want 422", resp2.StatusCode)
	}
}

// TestSavedSearch_CreateValidation_NlQueryLength tests that nl_query exceeding 1000
// characters is rejected with 422.
func TestSavedSearch_CreateValidation_NlQueryLength(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-nllen@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-nllen@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Exactly 1000 characters should succeed.
	nlQuery1000 := strings.Repeat("x", 1000)
	body := fmt.Sprintf(`{"name":"NL Len OK","query_json":%s,"nl_query":"%s"}`, validDSLJSON, nlQuery1000)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("nl_query 1000 chars: got %d, want 201", resp.StatusCode)
	}

	// 1001 characters should be rejected.
	nlQuery1001 := strings.Repeat("x", 1001)
	body2 := fmt.Sprintf(`{"name":"NL Len Bad","query_json":%s,"nl_query":"%s"}`, validDSLJSON, nlQuery1001)
	resp2 := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body2)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("nl_query 1001 chars: got %d, want 422", resp2.StatusCode)
	}
}

// TestSavedSearch_PatchValidation tests patch-specific validation: empty name,
// name length, and nl_query length constraints.
func TestSavedSearch_PatchValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-patchval@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-patchval@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Create a search to patch.
	body := fmt.Sprintf(`{"name":"Patch Target","query_json":%s}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var created savedSearchEntry
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Patch with empty name → 400.
	resp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID, `{"name":""}`)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty name: got %d, want 400", resp.StatusCode)
	}

	// Patch with name > 255 → 422.
	resp2 := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID,
		fmt.Sprintf(`{"name":"%s"}`, strings.Repeat("b", 256)))
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("name 256 chars: got %d, want 422", resp2.StatusCode)
	}

	// Patch with nl_query > 1000 → 422.
	resp3 := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID,
		fmt.Sprintf(`{"nl_query":"%s"}`, strings.Repeat("z", 1001)))
	defer resp3.Body.Close() //nolint:errcheck,gosec
	if resp3.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("nl_query 1001 chars: got %d, want 422", resp3.StatusCode)
	}
}

// TestSavedSearch_PrivateVisibility verifies that user B cannot see user A's
// private saved search, but can see shared searches.
func TestSavedSearch_PrivateVisibility(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	// Alice registers (becomes org owner).
	aliceReg := doRegister(t, ctx, ts, "ss-alice@example.com", "test-password-1234")
	aliceLoginResp := doLogin(t, ctx, ts, "ss-alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec
	aliceToken := cookieValue(aliceLoginResp, "access_token")

	// Bob registers separately, then gets invited to Alice's org as a member.
	doRegister(t, ctx, ts, "ss-bob@example.com", "test-password-1234")

	// Invite Bob.
	invResp := doCreateInvitation(t, ctx, ts, aliceToken, aliceReg.OrgID, "ss-bob@example.com", "member")
	defer invResp.Body.Close() //nolint:errcheck,gosec
	if invResp.StatusCode != http.StatusAccepted {
		t.Fatalf("invite bob: got %d, want 202", invResp.StatusCode)
	}

	// Get invitation token from DB.
	orgID, _ := uuid.Parse(aliceReg.OrgID)
	invitations, err := db.ListOrgInvitations(ctx, orgID)
	if err != nil || len(invitations) == 0 {
		t.Fatalf("list invitations: err=%v, len=%d", err, len(invitations))
	}
	invToken := invitations[0].Token

	// Bob accepts invitation.
	bobLoginResp := doLogin(t, ctx, ts, "ss-bob@example.com", "test-password-1234")
	defer bobLoginResp.Body.Close() //nolint:errcheck,gosec
	bobToken := cookieValue(bobLoginResp, "access_token")

	acceptResp := doAcceptInvitation(t, ctx, ts, bobToken, invToken)
	defer acceptResp.Body.Close() //nolint:errcheck,gosec
	if acceptResp.StatusCode != http.StatusOK {
		t.Fatalf("bob accept invitation: got %d, want 200", acceptResp.StatusCode)
	}

	// Re-login Bob to get updated JWT with new org membership.
	bobLoginResp2 := doLogin(t, ctx, ts, "ss-bob@example.com", "test-password-1234")
	defer bobLoginResp2.Body.Close() //nolint:errcheck,gosec
	bobToken = cookieValue(bobLoginResp2, "access_token")

	// Alice creates a private saved search.
	body := fmt.Sprintf(`{"name":"Alice Private","query_json":%s,"is_shared":false}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, aliceToken, aliceReg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create: got %d, want 201", createResp.StatusCode)
	}
	var created savedSearchEntry
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck,gosec

	// Alice creates a shared saved search.
	sharedBody := fmt.Sprintf(`{"name":"Alice Shared","query_json":%s,"is_shared":true}`, validDSLJSON)
	createSharedResp := doCreateSavedSearch(t, ctx, ts, aliceToken, aliceReg.OrgID, sharedBody)
	defer createSharedResp.Body.Close() //nolint:errcheck,gosec
	if createSharedResp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create shared: got %d, want 201", createSharedResp.StatusCode)
	}

	// Bob tries to GET Alice's private search → 404 (don't reveal existence).
	getResp := doGetSavedSearch(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("bob get private: got %d, want 404", getResp.StatusCode)
	}

	// Bob lists with visibility=shared → should see only the shared search.
	listResp := doListSavedSearches(t, ctx, ts, bobToken, aliceReg.OrgID, "shared")
	defer listResp.Body.Close() //nolint:errcheck,gosec
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("bob list shared: got %d, want 200", listResp.StatusCode)
	}
	var listResult listResponse[savedSearchEntry]
	json.NewDecoder(listResp.Body).Decode(&listResult) //nolint:errcheck,gosec
	if len(listResult.Items) != 1 {
		t.Fatalf("bob shared list len = %d, want 1", len(listResult.Items))
	}
	if listResult.Items[0].Name != "Alice Shared" {
		t.Errorf("expected Alice Shared, got %q", listResult.Items[0].Name)
	}
}

// TestSavedSearch_Execute creates a saved search, seeds CVEs, executes, and
// verifies matching results are returned.
func TestSavedSearch_Execute(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	// Seed CVEs.
	db.SeedTestCVE(t, "CVE-2025-0001", "critical", nil)
	db.SeedTestCVE(t, "CVE-2025-0002", "high", nil)
	db.SeedTestCVE(t, "CVE-2025-0003", "low", nil) // should not match

	reg := doRegister(t, ctx, ts, "ss-exec@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-exec@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Create saved search for severity in [critical, high].
	body := fmt.Sprintf(`{"name":"Exec Test","query_json":%s,"is_shared":false}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		var errBody json.RawMessage
		json.NewDecoder(createResp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("create: got %d, want 201; body: %s", createResp.StatusCode, errBody)
	}
	var created savedSearchEntry
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck,gosec

	// Execute.
	execResp := doExecuteSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID)
	defer execResp.Body.Close() //nolint:errcheck,gosec
	if execResp.StatusCode != http.StatusOK {
		var errBody json.RawMessage
		json.NewDecoder(execResp.Body).Decode(&errBody) //nolint:errcheck,gosec
		t.Fatalf("execute: got %d, want 200; body: %s", execResp.StatusCode, errBody)
	}

	var result savedSearchExecuteResponse
	if err := json.NewDecoder(execResp.Body).Decode(&result); err != nil {
		t.Fatalf("decode execute response: %v", err)
	}
	if len(result.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(result.Results))
	}
}

// TestSavedSearch_DeleteReturns404 verifies that after soft-delete, GET returns 404.
func TestSavedSearch_DeleteReturns404(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-del404@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-del404@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Create.
	body := fmt.Sprintf(`{"name":"Will Delete","query_json":%s}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var created savedSearchEntry
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck,gosec

	// Delete.
	delResp := doDeleteSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204", delResp.StatusCode)
	}

	// GET after delete → 404.
	getResp := doGetSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec
	if getResp.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete: got %d, want 404", getResp.StatusCode)
	}
}

// inviteAndLogin registers a user, invites them to the given org with the given
// role, accepts the invitation, and re-logins to get an updated JWT. Returns
// the access token for the newly-joined user.
func inviteAndLogin(t *testing.T, ctx context.Context, db *testutil.TestDB, ts *httptest.Server, ownerToken, orgID, email, role string) string {
	t.Helper()
	// Register.
	doRegister(t, ctx, ts, email, "test-password-1234")

	// Invite.
	invResp := doCreateInvitation(t, ctx, ts, ownerToken, orgID, email, role)
	defer invResp.Body.Close() //nolint:errcheck,gosec
	if invResp.StatusCode != http.StatusAccepted {
		t.Fatalf("invite %s as %s: got %d, want 202", email, role, invResp.StatusCode)
	}

	// Get invitation token from DB.
	oid, _ := uuid.Parse(orgID)
	invitations, err := db.ListOrgInvitations(ctx, oid)
	if err != nil || len(invitations) == 0 {
		t.Fatalf("list invitations for %s: err=%v, len=%d", email, err, len(invitations))
	}
	// Use the most recent invitation (last one).
	invToken := invitations[len(invitations)-1].Token

	// Login, accept, re-login for updated JWT.
	loginResp := doLogin(t, ctx, ts, email, "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	acceptResp := doAcceptInvitation(t, ctx, ts, token, invToken)
	defer acceptResp.Body.Close() //nolint:errcheck,gosec
	if acceptResp.StatusCode != http.StatusOK {
		t.Fatalf("%s accept invitation: got %d, want 200", email, acceptResp.StatusCode)
	}

	loginResp2 := doLogin(t, ctx, ts, email, "test-password-1234")
	defer loginResp2.Body.Close() //nolint:errcheck,gosec
	return cookieValue(loginResp2, "access_token")
}

// TestSavedSearch_RBAC tests canModifySavedSearch branches and route-level role
// checks: admin can modify shared, member cannot modify others' shared, nobody
// can modify others' private, viewer is denied POST/PATCH/DELETE by middleware.
func TestSavedSearch_RBAC(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSavedSearchTestServer(t, db)

	// Widen auth rate limiter: this test registers+logins 4 users (>10 auth calls).
	srv.rateLimiter.Stop()
	srv.rateLimiter = newIPRateLimiter(rate.Limit(100), 100, time.Minute)

	// Alice registers (becomes org owner).
	aliceReg := doRegister(t, ctx, ts, "rbac-alice@example.com", "test-password-1234")
	aliceLoginResp := doLogin(t, ctx, ts, "rbac-alice@example.com", "test-password-1234")
	defer aliceLoginResp.Body.Close() //nolint:errcheck,gosec
	aliceToken := cookieValue(aliceLoginResp, "access_token")
	orgID := aliceReg.OrgID

	// Upgrade to enterprise tier for generous org rate limits (1000 req/min).
	oid := mustParseUUID(t, orgID)
	if err := db.UpdateOrgTier(ctx, oid, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(oid)

	// Invite Charlie as admin, Dave as member, Eve as viewer.
	charlieToken := inviteAndLogin(t, ctx, db, ts, aliceToken, orgID, "rbac-charlie@example.com", "admin")
	daveToken := inviteAndLogin(t, ctx, db, ts, aliceToken, orgID, "rbac-dave@example.com", "member")
	eveToken := inviteAndLogin(t, ctx, db, ts, aliceToken, orgID, "rbac-eve@example.com", "viewer")

	// Alice creates a shared saved search.
	sharedBody := fmt.Sprintf(`{"name":"Shared Search","query_json":%s,"is_shared":true}`, validDSLJSON)
	sharedResp := doCreateSavedSearch(t, ctx, ts, aliceToken, orgID, sharedBody)
	defer sharedResp.Body.Close() //nolint:errcheck,gosec
	if sharedResp.StatusCode != http.StatusCreated {
		t.Fatalf("create shared: got %d, want 201", sharedResp.StatusCode)
	}
	var shared savedSearchEntry
	json.NewDecoder(sharedResp.Body).Decode(&shared) //nolint:errcheck,gosec

	// Alice creates a private saved search.
	privateBody := fmt.Sprintf(`{"name":"Private Search","query_json":%s,"is_shared":false}`, validDSLJSON)
	privateResp := doCreateSavedSearch(t, ctx, ts, aliceToken, orgID, privateBody)
	defer privateResp.Body.Close() //nolint:errcheck,gosec
	if privateResp.StatusCode != http.StatusCreated {
		t.Fatalf("create private: got %d, want 201", privateResp.StatusCode)
	}
	var private savedSearchEntry
	json.NewDecoder(privateResp.Body).Decode(&private) //nolint:errcheck,gosec

	// ── canModifySavedSearch branch 2: non-creator admin CAN patch shared search
	t.Run("AdminCanPatchShared", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, charlieToken, orgID, shared.ID, `{"name":"Admin Renamed"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			var body json.RawMessage
			json.NewDecoder(resp.Body).Decode(&body) //nolint:errcheck,gosec
			t.Errorf("admin patch shared: got %d, want 200; body: %s", resp.StatusCode, body)
		}
	})

	// ── canModifySavedSearch branch 2: non-creator admin CAN delete shared search
	// (We create a fresh shared search so deletion doesn't interfere with other tests.)
	t.Run("AdminCanDeleteShared", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":"Admin Delete Me","query_json":%s,"is_shared":true}`, validDSLJSON)
		cr := doCreateSavedSearch(t, ctx, ts, aliceToken, orgID, body)
		defer cr.Body.Close() //nolint:errcheck,gosec
		if cr.StatusCode != http.StatusCreated {
			t.Fatalf("create for admin delete: got %d", cr.StatusCode)
		}
		var entry savedSearchEntry
		json.NewDecoder(cr.Body).Decode(&entry) //nolint:errcheck,gosec

		resp := doDeleteSavedSearch(t, ctx, ts, charlieToken, orgID, entry.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("admin delete shared: got %d, want 204", resp.StatusCode)
		}
	})

	// ── canModifySavedSearch branch 3: non-creator member DENIED on shared search
	t.Run("MemberDeniedPatchShared", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, daveToken, orgID, shared.ID, `{"name":"Dave Rename"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("member patch shared: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("MemberDeniedDeleteShared", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, daveToken, orgID, shared.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("member delete shared: got %d, want 403", resp.StatusCode)
		}
	})

	// ── canModifySavedSearch branch 4: non-creator DENIED on private search
	// Patch/delete handlers fetch the row via GetSavedSearch (no visibility filter),
	// then canModifySavedSearch returns false (not creator, not shared) → 403.
	t.Run("AdminDeniedPatchPrivate", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, charlieToken, orgID, private.ID, `{"name":"Admin Rename Private"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("admin patch private (not creator): got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("MemberDeniedDeletePrivate", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, daveToken, orgID, private.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("member delete private (not creator): got %d, want 403", resp.StatusCode)
		}
	})

	// ── Route-level RBAC: viewer denied POST, PATCH, DELETE (requires member+)
	t.Run("ViewerDeniedCreate", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":"Eve Search","query_json":%s}`, validDSLJSON)
		resp := doCreateSavedSearch(t, ctx, ts, eveToken, orgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer create: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("ViewerDeniedPatch", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, eveToken, orgID, shared.ID, `{"name":"Eve Rename"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer patch: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("ViewerDeniedDelete", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, eveToken, orgID, shared.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer delete: got %d, want 403", resp.StatusCode)
		}
	})

	// ── Private access check: non-creator cannot execute private search
	t.Run("NonCreatorDeniedExecutePrivate", func(t *testing.T) {
		resp := doExecuteSavedSearch(t, ctx, ts, daveToken, orgID, private.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("non-creator execute private: got %d, want 404", resp.StatusCode)
		}
	})

	// ── Positive: viewer CAN get and execute shared searches
	t.Run("ViewerCanGetShared", func(t *testing.T) {
		resp := doGetSavedSearch(t, ctx, ts, eveToken, orgID, shared.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer get shared: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("ViewerCanExecuteShared", func(t *testing.T) {
		resp := doExecuteSavedSearch(t, ctx, ts, eveToken, orgID, shared.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer execute shared: got %d, want 200", resp.StatusCode)
		}
	})
}

// ── Malformed JSON, invalid UUID, not-found, visibility filter tests ────────

func TestSavedSearch_CreateMalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ssbadjson@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ssbadjson@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, `{not valid json`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("create malformed JSON: got %d, want 400", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var prob struct {
		Status int `json:"status"`
		Errors []struct {
			Location string `json:"location"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if prob.Status != 400 {
		t.Errorf("problem status = %d, want 400", prob.Status)
	}
	if len(prob.Errors) == 0 {
		t.Fatal("expected errors array with at least one entry")
	}
	if prob.Errors[0].Location != "body" {
		t.Errorf("errors[0].location = %q, want %q", prob.Errors[0].Location, "body")
	}
}

func TestSavedSearch_PatchMalformedJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "sspatchbad@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sspatchbad@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Create a valid search first.
	body := fmt.Sprintf(`{"name":"For Patch","query_json":%s,"is_shared":false}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	var created savedSearchEntry
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck,gosec

	resp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, created.ID, `{not valid json`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("patch malformed JSON: got %d, want 400", resp.StatusCode)
	}
}

func TestSavedSearch_InvalidUUID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ssuuid@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ssuuid@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	badID := "not-a-valid-uuid"

	t.Run("Get", func(t *testing.T) {
		resp := doGetSavedSearch(t, ctx, ts, token, reg.OrgID, badID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("get invalid UUID: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Patch", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, badID, `{"name":"x"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("patch invalid UUID: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, token, reg.OrgID, badID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("delete invalid UUID: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Execute", func(t *testing.T) {
		resp := doExecuteSavedSearch(t, ctx, ts, token, reg.OrgID, badID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("execute invalid UUID: got %d, want 400", resp.StatusCode)
		}
	})
}

func TestSavedSearch_PatchNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "sspatchnf@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sspatchnf@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	nonexistentID := uuid.New().String()
	resp := doPatchSavedSearch(t, ctx, ts, token, reg.OrgID, nonexistentID, `{"name":"Ghost"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("patch nonexistent: got %d, want 404", resp.StatusCode)
	}
}

func TestSavedSearch_ExecuteNotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ssexecnf@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ssexecnf@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	nonexistentID := uuid.New().String()
	resp := doExecuteSavedSearch(t, ctx, ts, token, reg.OrgID, nonexistentID)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("execute nonexistent: got %d, want 404", resp.StatusCode)
	}
}

// ── orgID fail-closed: non-UUID org_id in URL → 400 ─────────────────────────

func TestSavedSearch_InvalidOrgID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-badorgid@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-badorgid@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")
	_ = reg // only needed for registration side effect

	badOrg := "not-a-uuid"

	t.Run("Create", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":"X","query_json":%s}`, validDSLJSON)
		resp := doCreateSavedSearch(t, ctx, ts, token, badOrg, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("List", func(t *testing.T) {
		resp := doListSavedSearches(t, ctx, ts, token, badOrg, "")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("list invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Get", func(t *testing.T) {
		resp := doGetSavedSearch(t, ctx, ts, token, badOrg, uuid.New().String())
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("get invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Patch", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, token, badOrg, uuid.New().String(), `{"name":"x"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("patch invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, token, badOrg, uuid.New().String())
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("delete invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
	t.Run("Execute", func(t *testing.T) {
		resp := doExecuteSavedSearch(t, ctx, ts, token, badOrg, uuid.New().String())
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("execute invalid org_id: got %d, want 400", resp.StatusCode)
		}
	})
}

// ── Cross-org tenant isolation: user A cannot CRUD in org B ──────────────────

func TestSavedSearch_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	// User A: first registered user gets auto-created org.
	regA := doRegister(t, ctx, ts, "ss-orgA@example.com", "test-password-1234")

	loginA := doLogin(t, ctx, ts, "ss-orgA@example.com", "test-password-1234")
	defer loginA.Body.Close() //nolint:errcheck,gosec
	tokenA := cookieValue(loginA, "access_token")

	// User B: second user must create their own org explicitly
	// (BootstrapFirstUserOrg only fires for the first registration).
	doRegister(t, ctx, ts, "ss-orgB@example.com", "test-password-1234")
	loginB := doLogin(t, ctx, ts, "ss-orgB@example.com", "test-password-1234")
	defer loginB.Body.Close() //nolint:errcheck,gosec
	tokenB := cookieValue(loginB, "access_token")

	orgBResp := doCreateOrg(t, ctx, ts, tokenB, "SS Org B")
	defer orgBResp.Body.Close() //nolint:errcheck,gosec
	if orgBResp.StatusCode != http.StatusCreated {
		t.Fatalf("create org B: got %d, want 201", orgBResp.StatusCode)
	}
	var orgB struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(orgBResp.Body).Decode(&orgB); err != nil {
		t.Fatalf("decode org B: %v", err)
	}

	// User B creates a shared saved search in org B.
	body := fmt.Sprintf(`{"name":"Org B Search","query_json":%s,"is_shared":true}`, validDSLJSON)
	createResp := doCreateSavedSearch(t, ctx, ts, tokenB, orgB.OrgID, body)
	defer createResp.Body.Close() //nolint:errcheck,gosec
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("org B create: got %d, want 201", createResp.StatusCode)
	}
	var created savedSearchEntry
	json.NewDecoder(createResp.Body).Decode(&created) //nolint:errcheck,gosec

	// User A (org A) tries to access org B's endpoints → all forbidden.
	t.Run("Create", func(t *testing.T) {
		body := fmt.Sprintf(`{"name":"X","query_json":%s}`, validDSLJSON)
		resp := doCreateSavedSearch(t, ctx, ts, tokenA, orgB.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org create: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("List", func(t *testing.T) {
		resp := doListSavedSearches(t, ctx, ts, tokenA, orgB.OrgID, "")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org list: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("Get", func(t *testing.T) {
		resp := doGetSavedSearch(t, ctx, ts, tokenA, orgB.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org get: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("Patch", func(t *testing.T) {
		resp := doPatchSavedSearch(t, ctx, ts, tokenA, orgB.OrgID, created.ID, `{"name":"hacked"}`)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org patch: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("Delete", func(t *testing.T) {
		resp := doDeleteSavedSearch(t, ctx, ts, tokenA, orgB.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org delete: got %d, want 403", resp.StatusCode)
		}
	})
	t.Run("Execute", func(t *testing.T) {
		resp := doExecuteSavedSearch(t, ctx, ts, tokenA, orgB.OrgID, created.ID)
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("cross-org execute: got %d, want 403", resp.StatusCode)
		}
	})

	// Sanity: User A accessing own org works.
	t.Run("OwnOrgWorks", func(t *testing.T) {
		resp := doListSavedSearches(t, ctx, ts, tokenA, regA.OrgID, "")
		defer resp.Body.Close() //nolint:errcheck,gosec
		if resp.StatusCode == http.StatusForbidden {
			t.Error("own-org list should not be 403")
		}
	})
}

// ── Unauthenticated create → 401 ────────────────────────────────────────────

func TestSavedSearch_CreateUnauthenticated(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-noauth@example.com", "test-password-1234")

	body := fmt.Sprintf(`{"name":"Sneaky","query_json":%s}`, validDSLJSON)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+reg.OrgID+"/saved-searches",
		bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	// No Cookie header — unauthenticated.

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("unauthenticated create: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated create: got %d, want 401", resp.StatusCode)
	}
}

// ── Contract tests: Location header, list envelope, validation error format ──

func TestCreateSavedSearch_LocationHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-loc@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-loc@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	body := fmt.Sprintf(`{"name":"Loc Test","query_json":%s}`, validDSLJSON)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", resp.StatusCode)
	}

	var created savedSearchEntry
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("Location header is empty")
	}
	if !strings.Contains(loc, created.ID) {
		t.Errorf("Location %q does not contain search ID %q", loc, created.ID)
	}
}

func TestListSavedSearches_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-env@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-env@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doListSavedSearches(t, ctx, ts, token, reg.OrgID, "")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: got %d, want 200", resp.StatusCode)
	}

	// Verify the response has "items" key by decoding into a map.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["items"]; !ok {
		t.Fatal("response missing 'items' key")
	}
}

func TestCreateSavedSearch_ValidationErrorFormat(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ss-valerr@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ss-valerr@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	// Send empty name to trigger validation error.
	body := fmt.Sprintf(`{"name":"","query_json":%s}`, validDSLJSON)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("empty name: got %d, want 422", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var prob struct {
		Status int `json:"status"`
		Errors []struct {
			Location string `json:"location"`
			Message  string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prob); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if len(prob.Errors) == 0 {
		t.Fatal("expected errors array with at least one entry")
	}
	if prob.Errors[0].Location != "body.name" {
		t.Errorf("errors[0].location = %q, want %q", prob.Errors[0].Location, "body.name")
	}
}

func TestSavedSearch_InvalidVisibility(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSavedSearchTestServer(t, db)

	reg := doRegister(t, ctx, ts, "ssvis@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "ssvis@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")

	resp := doListSavedSearches(t, ctx, ts, token, reg.OrgID, "bogus")
	defer resp.Body.Close() //nolint:errcheck,gosec

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid visibility: got %d, want 400", resp.StatusCode)
	}
}
