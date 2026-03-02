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

// validRuleDSL is a simple valid enabled rule DSL for testing. Creates in "activating" status.
const validRuleDSL = `{
  "name": "High CVSS Rule",
  "logic": "and",
  "conditions": [{"field": "cvss_v3_score", "operator": "gte", "value": 7.0}],
  "watchlist_ids": [],
  "enabled": true,
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
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create alert rule: got %d, want 201", createResp.StatusCode)
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

	// PATCH: update the name only while activating → 200, status stays activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID, `{"name":"Renamed Rule"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("patch alert rule: got %d, want 200", patchResp.StatusCode)
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

// TestAlertRule_Draft verifies creating a rule with enabled=false returns 201 with status=draft.
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
  "enabled": false
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
// Rule must be in "active" status; DSL changes on "activating" rules return 409.
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
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Transition to active so DSL changes are allowed (activating → 409).
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, created.ID)
	if err := db.SetAlertRuleStatus(ctx, orgUUID, ruleUUID, "active"); err != nil {
		t.Fatalf("set status to active: %v", err)
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
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d, want 201", createResp.StatusCode)
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

// ── Rule-channel binding helpers ──────────────────────────────────────────────

func doBindChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, ruleID, channelID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+ruleID+"/channels/"+channelID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("bind channel: %v", err)
	}
	return resp
}

func doUnbindChannel(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, ruleID, channelID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+ruleID+"/channels/"+channelID, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("unbind channel: %v", err)
	}
	return resp
}

func doListRuleChannels(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, ruleID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		ts.URL+"/api/v1/orgs/"+orgID+"/alert-rules/"+ruleID+"/channels", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list rule channels: %v", err)
	}
	return resp
}

// ── Rule-channel binding tests ────────────────────────────────────────────────

// TestBindChannelToRule_Idempotent verifies that binding a channel to a rule is idempotent:
// the second PUT returns 204 just like the first.
func TestBindChannelToRule_Idempotent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createChanResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createChanResp.Body.Close() //nolint:errcheck,gosec // G104
	if createChanResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createChanResp.StatusCode)
	}
	var createdChan struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChanResp.Body).Decode(&createdChan); err != nil {
		t.Fatalf("decode create channel: %v", err)
	}

	createRuleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create alert rule: got %d, want 201", createRuleResp.StatusCode)
	}
	var createdRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&createdRule); err != nil {
		t.Fatalf("decode create rule: %v", err)
	}

	// First bind → 204.
	bindResp1 := doBindChannel(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID, createdChan.ID)
	defer bindResp1.Body.Close() //nolint:errcheck,gosec // G104
	if bindResp1.StatusCode != http.StatusNoContent {
		t.Fatalf("first bind: got %d, want 204", bindResp1.StatusCode)
	}

	// Second bind (idempotent) → 204.
	bindResp2 := doBindChannel(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID, createdChan.ID)
	defer bindResp2.Body.Close() //nolint:errcheck,gosec // G104
	if bindResp2.StatusCode != http.StatusNoContent {
		t.Fatalf("second bind (idempotent): got %d, want 204", bindResp2.StatusCode)
	}
}

// TestBindChannelToRule_CrossOrgChannelRejected verifies that binding a channel from a different
// org returns 404 — the channel does not exist in the rule's org.
func TestBindChannelToRule_CrossOrgChannelRejected(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice is first user — auto-org assigned.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	// Bob is second user — no auto-org, so he creates one explicitly.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	createOrgReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs", bytes.NewBufferString(`{"name":"Bob Org"}`))
	createOrgReq.Header.Set("Content-Type", "application/json")
	createOrgReq.Header.Set("Cookie", "access_token="+bobToken)
	createOrgReq.Header.Set("X-Requested-By", "CVErt-Ops")
	createOrgResp, err := ts.Client().Do(createOrgReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create bob org: %v", err)
	}
	defer createOrgResp.Body.Close() //nolint:errcheck,gosec // G104
	if createOrgResp.StatusCode != http.StatusCreated {
		t.Fatalf("create bob org: got %d, want 201", createOrgResp.StatusCode)
	}
	var bobOrg struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(createOrgResp.Body).Decode(&bobOrg); err != nil {
		t.Fatalf("decode bob org: %v", err)
	}

	// Alice creates a rule in her org.
	createRuleResp := doCreateAlertRule(t, ctx, ts, aliceToken, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusCreated {
		t.Fatalf("alice create rule: got %d, want 201", createRuleResp.StatusCode)
	}
	var aliceRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&aliceRule); err != nil {
		t.Fatalf("decode alice rule: %v", err)
	}

	// Bob creates a channel in his org.
	createChanResp := doCreateChannel(t, ctx, ts, bobToken, bobOrg.OrgID, validChannelBody)
	defer createChanResp.Body.Close() //nolint:errcheck,gosec // G104
	if createChanResp.StatusCode != http.StatusCreated {
		t.Fatalf("bob create channel: got %d, want 201", createChanResp.StatusCode)
	}
	var bobChan struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChanResp.Body).Decode(&bobChan); err != nil {
		t.Fatalf("decode bob channel: %v", err)
	}

	// Alice tries to bind Bob's channel to her rule → 404.
	bindResp := doBindChannel(t, ctx, ts, aliceToken, aliceReg.OrgID, aliceRule.ID, bobChan.ID)
	defer bindResp.Body.Close() //nolint:errcheck,gosec // G104
	if bindResp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-org bind: got %d, want 404", bindResp.StatusCode)
	}
}

// TestUnbindChannelFromRule_204 verifies that unbinding an existing binding returns 204.
func TestUnbindChannelFromRule_204(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createChanResp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, validChannelBody)
	defer createChanResp.Body.Close() //nolint:errcheck,gosec // G104
	if createChanResp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel: got %d, want 201", createChanResp.StatusCode)
	}
	var createdChan struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChanResp.Body).Decode(&createdChan); err != nil {
		t.Fatalf("decode create channel: %v", err)
	}

	createRuleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create alert rule: got %d, want 201", createRuleResp.StatusCode)
	}
	var createdRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&createdRule); err != nil {
		t.Fatalf("decode create rule: %v", err)
	}

	// Bind via store directly.
	if err := db.BindChannelToRule(ctx,
		mustParseUUID(t, createdRule.ID),
		mustParseUUID(t, createdChan.ID),
		mustParseUUID(t, aliceReg.OrgID),
	); err != nil {
		t.Fatalf("bind channel to rule: %v", err)
	}

	// DELETE → 204.
	unbindResp := doUnbindChannel(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID, createdChan.ID)
	defer unbindResp.Body.Close() //nolint:errcheck,gosec // G104
	if unbindResp.StatusCode != http.StatusNoContent {
		t.Fatalf("unbind: got %d, want 204", unbindResp.StatusCode)
	}
}

// TestUnbindChannelFromRule_404 verifies that unbinding a non-existent binding returns 404.
func TestUnbindChannelFromRule_404(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createRuleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create alert rule: got %d, want 201", createRuleResp.StatusCode)
	}
	var createdRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&createdRule); err != nil {
		t.Fatalf("decode create rule: %v", err)
	}

	// Use a random UUID as channel_id — binding doesn't exist.
	fakeChannelID := "00000000-0000-0000-0000-000000000001"
	unbindResp := doUnbindChannel(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID, fakeChannelID)
	defer unbindResp.Body.Close() //nolint:errcheck,gosec // G104
	if unbindResp.StatusCode != http.StatusNotFound {
		t.Fatalf("unbind non-existent binding: got %d, want 404", unbindResp.StatusCode)
	}
}

// TestListChannelsForRule verifies listing channels for a rule, and that soft-deleted channels
// are excluded from results.
func TestListChannelsForRule(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create 2 channels.
	createChan1Resp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Channel 1","type":"webhook","config":{"url":"https://example.com/hook1"}}`)
	defer createChan1Resp.Body.Close() //nolint:errcheck,gosec // G104
	if createChan1Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel 1: got %d, want 201", createChan1Resp.StatusCode)
	}
	var chan1 struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChan1Resp.Body).Decode(&chan1); err != nil {
		t.Fatalf("decode channel 1: %v", err)
	}

	createChan2Resp := doCreateChannel(t, ctx, ts, token, aliceReg.OrgID, `{"name":"Channel 2","type":"webhook","config":{"url":"https://example.com/hook2"}}`)
	defer createChan2Resp.Body.Close() //nolint:errcheck,gosec // G104
	if createChan2Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create channel 2: got %d, want 201", createChan2Resp.StatusCode)
	}
	var chan2 struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createChan2Resp.Body).Decode(&chan2); err != nil {
		t.Fatalf("decode channel 2: %v", err)
	}

	// Create a rule.
	createRuleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createRuleResp.Body.Close() //nolint:errcheck,gosec // G104
	if createRuleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create alert rule: got %d, want 201", createRuleResp.StatusCode)
	}
	var createdRule struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createRuleResp.Body).Decode(&createdRule); err != nil {
		t.Fatalf("decode create rule: %v", err)
	}

	// Bind both channels via store.
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, createdRule.ID)
	if err := db.BindChannelToRule(ctx, ruleUUID, mustParseUUID(t, chan1.ID), orgUUID); err != nil {
		t.Fatalf("bind channel 1: %v", err)
	}
	if err := db.BindChannelToRule(ctx, ruleUUID, mustParseUUID(t, chan2.ID), orgUUID); err != nil {
		t.Fatalf("bind channel 2: %v", err)
	}

	// GET → 2 items.
	listResp := doListRuleChannels(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID)
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list rule channels: got %d, want 200", listResp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Items) != 2 {
		t.Fatalf("list items count = %d, want 2", len(listed.Items))
	}

	// Soft-delete channel 1 via store.
	if err := db.SoftDeleteNotificationChannel(ctx, orgUUID, mustParseUUID(t, chan1.ID)); err != nil {
		t.Fatalf("soft delete channel 1: %v", err)
	}

	// GET again → 1 item (deleted channel excluded).
	listResp2 := doListRuleChannels(t, ctx, ts, token, aliceReg.OrgID, createdRule.ID)
	defer listResp2.Body.Close() //nolint:errcheck,gosec // G104
	if listResp2.StatusCode != http.StatusOK {
		t.Fatalf("list rule channels after delete: got %d, want 200", listResp2.StatusCode)
	}
	var listed2 struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(listResp2.Body).Decode(&listed2); err != nil {
		t.Fatalf("decode list 2: %v", err)
	}
	if len(listed2.Items) != 1 {
		t.Fatalf("list items count after soft-delete = %d, want 1", len(listed2.Items))
	}
}

// ── PATCH state machine tests ─────────────────────────────────────────────────

// TestPatchStateMachine_ActivatingDSLChange verifies that PATCH with DSL change
// on an activating rule returns 409 Conflict.
func TestPatchStateMachine_ActivatingDSLChange(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create rule — starts in "activating".
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// PATCH with DSL change (conditions) while activating → 409.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusConflict {
		t.Fatalf("activating + DSL change: got %d, want 409", patchResp.StatusCode)
	}
}

// TestPatchStateMachine_ActivatingNameOnly verifies that PATCH with name-only
// change on an activating rule returns 200 and keeps status=activating.
func TestPatchStateMachine_ActivatingNameOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// PATCH with name only while activating → 200, status stays activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"name":"Renamed While Activating"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("activating + name only: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Name != "Renamed While Activating" {
		t.Errorf("name = %q, want %q", patched.Name, "Renamed While Activating")
	}
	if patched.Status != "activating" {
		t.Errorf("status = %q, want %q", patched.Status, "activating")
	}
}

// TestPatchStateMachine_ActiveDSLChange verifies that PATCH with DSL change on
// an active rule returns 200 and transitions status to activating.
func TestPatchStateMachine_ActiveDSLChange(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// Transition to active via store.
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, created.ID)
	if err := db.SetAlertRuleStatus(ctx, orgUUID, ruleUUID, "active"); err != nil {
		t.Fatalf("set status to active: %v", err)
	}

	// PATCH with DSL change on active rule → 200, status=activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("active + DSL change: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Status != "activating" {
		t.Errorf("status = %q, want %q", patched.Status, "activating")
	}
}

// TestPatchStateMachine_ActiveNameOnly verifies that PATCH with name-only change
// on an active rule returns 200 with status staying active.
func TestPatchStateMachine_ActiveNameOnly(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// Transition to active via store.
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, created.ID)
	if err := db.SetAlertRuleStatus(ctx, orgUUID, ruleUUID, "active"); err != nil {
		t.Fatalf("set status to active: %v", err)
	}

	// PATCH with name only on active rule → 200, status=active.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"name":"Active Renamed"}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("active + name only: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Name != "Active Renamed" {
		t.Errorf("name = %q, want %q", patched.Name, "Active Renamed")
	}
	if patched.Status != "active" {
		t.Errorf("status = %q, want %q", patched.Status, "active")
	}
}

// TestPatchStateMachine_DraftEnableTrue verifies that PATCH with enabled=true
// on a draft rule transitions to activating.
func TestPatchStateMachine_DraftEnableTrue(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create a draft rule (enabled=false).
	const draftBody = `{
  "name": "Draft Rule",
  "logic": "and",
  "conditions": [{"field": "in_cisa_kev", "operator": "eq", "value": true}],
  "watchlist_ids": [],
  "enabled": false
}`
	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, draftBody)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)
	if created.Status != "draft" {
		t.Fatalf("created status = %q, want draft", created.Status)
	}

	// PATCH with enabled=true on draft → 200, status=activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"enabled":true}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("draft + enabled=true: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Status != "activating" {
		t.Errorf("status = %q, want %q", patched.Status, "activating")
	}
}

// TestPatchStateMachine_ActiveDisable verifies that PATCH with enabled=false
// on an active rule transitions to disabled.
func TestPatchStateMachine_ActiveDisable(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// Transition to active via store.
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, created.ID)
	if err := db.SetAlertRuleStatus(ctx, orgUUID, ruleUUID, "active"); err != nil {
		t.Fatalf("set status to active: %v", err)
	}

	// PATCH with enabled=false on active → 200, status=disabled.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"enabled":false}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("active + enabled=false: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Status != "disabled" {
		t.Errorf("status = %q, want %q", patched.Status, "disabled")
	}
}

// TestPatchStateMachine_ErrorEnableTrue verifies that PATCH with enabled=true
// on an error-state rule transitions to activating.
func TestPatchStateMachine_ErrorEnableTrue(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	createResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer createResp.Body.Close() //nolint:errcheck,gosec // G104
	var created struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(createResp.Body).Decode(&created)

	// Transition to error via store.
	orgUUID := mustParseUUID(t, aliceReg.OrgID)
	ruleUUID := mustParseUUID(t, created.ID)
	if err := db.SetAlertRuleStatus(ctx, orgUUID, ruleUUID, "error"); err != nil {
		t.Fatalf("set status to error: %v", err)
	}

	// PATCH with enabled=true on error → 200, status=activating.
	patchResp := doPatchAlertRule(t, ctx, ts, token, aliceReg.OrgID, created.ID,
		`{"enabled":true}`)
	defer patchResp.Body.Close() //nolint:errcheck,gosec // G104
	if patchResp.StatusCode != http.StatusOK {
		t.Fatalf("error + enabled=true: got %d, want 200", patchResp.StatusCode)
	}
	var patched struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(patchResp.Body).Decode(&patched)
	if patched.Status != "activating" {
		t.Errorf("status = %q, want %q", patched.Status, "activating")
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
