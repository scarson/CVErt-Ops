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
	"testing"

	"github.com/google/uuid"

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
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
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
	var items []savedSearchEntry
	if err := json.NewDecoder(listResp.Body).Decode(&items); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("list len = %d, want 1", len(items))
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

	// Empty name → 400
	body := fmt.Sprintf(`{"name":"","query_json":%s}`, validDSLJSON)
	resp := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty name: got %d, want 400", resp.StatusCode)
	}

	// Invalid DSL → 422
	body2 := `{"name":"Bad DSL","query_json":{"logic":"nope","conditions":[]}}`
	resp2 := doCreateSavedSearch(t, ctx, ts, token, reg.OrgID, body2)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("invalid DSL: got %d, want 422", resp2.StatusCode)
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
	var listItems []savedSearchEntry
	json.NewDecoder(listResp.Body).Decode(&listItems) //nolint:errcheck,gosec
	if len(listItems) != 1 {
		t.Fatalf("bob shared list len = %d, want 1", len(listItems))
	}
	if listItems[0].Name != "Alice Shared" {
		t.Errorf("expected Alice Shared, got %q", listItems[0].Name)
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
