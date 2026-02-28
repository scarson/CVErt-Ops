// ABOUTME: Integration tests for alert rule HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB and the full srv.Handler() stack.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helper functions ─────────────────────────────────────────────────────

func doCreateAlertRule(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create alert rule: %v", err)
	}
	return resp
}

func doGetAlertRule(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get alert rule: %v", err)
	}
	return resp
}

func doListAlertRules(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list alert rules: %v", err)
	}
	return resp
}

func doPatchAlertRule(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+id, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("patch alert rule: %v", err)
	}
	return resp
}

func doDeleteAlertRule(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("delete alert rule: %v", err)
	}
	return resp
}

func doValidateAlertRule(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/validate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("validate alert rule: %v", err)
	}
	return resp
}

// validRuleDSL is a simple valid rule DSL for testing.
const validRuleDSL = `{
  "name": "High CVSS Rule",
  "logic": "and",
  "conditions": [{"field": "cvss_v3_score", "operator": "gte", "value": 7.0}],
  "watchlist_ids": [],
  "fire_on_non_material_changes": false
}`

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAlertRuleCRUD verifies create, get, list, update, delete for alert rules.
func TestAlertRuleCRUD(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create returns 202 (activating scan queued).
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create alert rule: got %d, want 202", createResp.StatusCode)
	}
	var created struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("created alert rule has empty ID")
	}
	if created.Name != "High CVSS Rule" {
		t.Errorf("name = %q, want %q", created.Name, "High CVSS Rule")
	}
	if created.Status != "activating" {
		t.Errorf("status = %q, want %q", created.Status, "activating")
	}

	// Get
	getResp := doGetAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get alert rule: got %d, want 200", getResp.StatusCode)
	}
	var got struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("get id = %q, want %q", got.ID, created.ID)
	}

	// List
	listResp := doListAlertRules(t, ctx, ts, token, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list alert rules: got %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 1 {
		t.Fatalf("list items count = %d, want 1", len(listed.Items))
	}

	// PATCH: update the name. Status transitions back to activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID, `{"name":"Renamed Rule"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusAccepted {
		t.Fatalf("patch alert rule: got %d, want 202", patchResp.StatusCode)
	}
	var patched struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(patchResp.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched.Name != "Renamed Rule" {
		t.Errorf("patched name = %q, want %q", patched.Name, "Renamed Rule")
	}

	// Delete
	delResp := doDeleteAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer delResp.Body.Close() //nolint:errcheck,gosec // G104
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete alert rule: got %d, want 204", delResp.StatusCode)
	}

	// Verify deleted
	getAfterDel := doGetAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID)
	defer getAfterDel.Body.Close() //nolint:errcheck,gosec // G104
	if getAfterDel.StatusCode != http.StatusNotFound {
		t.Fatalf("get deleted: got %d, want 404", getAfterDel.StatusCode)
	}
}

// TestAlertRule_Draft verifies creating a rule with status=draft returns 201 and stays in draft.
func TestAlertRule_Draft(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	const draftBody = `{
  "name": "Draft Rule",
  "logic": "and",
  "conditions": [{"field": "in_cisa_kev", "operator": "eq", "value": true}],
  "watchlist_ids": [],
  "status": "draft"
}`
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, draftBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create draft rule: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create draft: %v", err)
	}
	if created.Status != "draft" {
		t.Errorf("status = %q, want %q", created.Status, "draft")
	}
}

// TestAlertRule_ValidateDSL verifies the /validate endpoint accepts valid DSL and rejects invalid.
func TestAlertRule_ValidateDSL(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Valid DSL
	validBody := `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"high"}]}`
	validResp := doValidateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validBody)
	defer validResp.Body.Close() //nolint:errcheck,gosec // G104
	if validResp.StatusCode != http.StatusOK {
		t.Fatalf("validate valid DSL: got %d, want 200", validResp.StatusCode)
	}
	var validResult struct {
		Valid  bool `json:"valid"`
		Errors []any `json:"errors"`
	}
	if err := json.NewDecoder(validResp.Body).Decode(&validResult); err != nil {
		t.Fatalf("decode validate result: %v", err)
	}
	if !validResult.Valid {
		t.Errorf("valid DSL reported as invalid: errors = %v", validResult.Errors)
	}

	// Invalid DSL: unknown field
	invalidBody := `{"logic":"and","conditions":[{"field":"nonexistent_field","operator":"eq","value":"x"}]}`
	invalidResp := doValidateAlertRule(t, ctx, ts, token, aliceReg.OrgID, invalidBody)
	defer invalidResp.Body.Close() //nolint:errcheck,gosec // G104
	if invalidResp.StatusCode != http.StatusOK {
		t.Fatalf("validate invalid DSL: got %d, want 200", invalidResp.StatusCode)
	}
	var invalidResult struct {
		Valid  bool `json:"valid"`
		Errors []any `json:"errors"`
	}
	if err := json.NewDecoder(invalidResp.Body).Decode(&invalidResult); err != nil {
		t.Fatalf("decode invalid validate result: %v", err)
	}
	if invalidResult.Valid {
		t.Error("invalid DSL reported as valid")
	}
	if len(invalidResult.Errors) == 0 {
		t.Error("invalid DSL: expected errors, got none")
	}
}

// TestAlertRule_InvalidDSL verifies that creating a rule with invalid DSL returns 422.
func TestAlertRule_InvalidDSL(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	const badDSL = `{
  "name": "Bad Rule",
  "logic": "and",
  "conditions": [{"field": "unknown_field", "operator": "eq", "value": "x"}],
  "watchlist_ids": []
}`
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, badDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("create with invalid DSL: got %d, want 422", createResp.StatusCode)
	}
}

// TestAlertRule_PatchInvalidDSL verifies that PATCH with invalid DSL conditions returns 422.
func TestAlertRule_PatchInvalidDSL(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create a valid rule.
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create: got %d, want 202", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// PATCH with an unknown DSL field — should return 422.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"conditions":[{"field":"unknown_field","operator":"eq","value":"x"}]}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("patch invalid DSL: got %d, want 422", patchResp.StatusCode)
	}
}

// TestAlertRule_CrossOrgIsolation verifies that a user cannot read or modify alert rules across org boundaries.
// Registration in "open" mode only auto-creates an org for the first user; Bob (second user) has no org
// and therefore cannot be a member of Alice's org.
func TestAlertRule_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is the first user — she gets an auto-org.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, aliceToken, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusAccepted {
		t.Fatalf("create: got %d, want 202", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Bob is the second user — he has no org and is not a member of Alice's org.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Bob cannot access Alice's org (not a member → 403).
	getResp := doGetAlertRule(t, ctx, ts, bobToken, aliceReg.OrgID, created.ID)
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org get: got %d, want 403", getResp.StatusCode)
	}

	listResp := doListAlertRules(t, ctx, ts, bobToken, aliceReg.OrgID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org list: got %d, want 403", listResp.StatusCode)
	}
}

// TestAlertRule_ViewerCannotWrite verifies that viewer role cannot create or delete alert rules.
func TestAlertRule_ViewerCannotWrite(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Create a viewer.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	_ = bobReg
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Invite bob as viewer to alice's org.
	inviteBody := `{"email":"bob@example.com","role":"viewer"}`
	inviteReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs/"+aliceReg.OrgID+"/invitations",
		bytes.NewBufferString(inviteBody))
	inviteReq.Header.Set("Content-Type", "application/json")
	inviteReq.Header.Set("Cookie", "access_token="+aliceToken)
	inviteReq.Header.Set("X-Requested-By", "CVErt-Ops")
	inviteResp, err := ts.Client().Do(inviteReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	defer inviteResp.Body.Close() //nolint:errcheck,gosec // G104

	var inv struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(inviteResp.Body).Decode(&inv); err != nil {
		t.Fatalf("decode invite: %v", err)
	}

	// Bob accepts the invitation.
	acceptReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/auth/accept-invitation",
		bytes.NewBufferString(`{"token":"`+inv.Token+`"}`))
	acceptReq.Header.Set("Content-Type", "application/json")
	acceptReq.Header.Set("Cookie", "access_token="+bobToken)
	acceptReq.Header.Set("X-Requested-By", "CVErt-Ops")
	acceptResp, err := ts.Client().Do(acceptReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	defer acceptResp.Body.Close() //nolint:errcheck,gosec // G104

	// Bob cannot create alert rules in alice's org.
	createResp := doCreateAlertRule(t, ctx, ts, bobToken, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	if createResp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer create: got %d, want 403", createResp.StatusCode)
	}
}
