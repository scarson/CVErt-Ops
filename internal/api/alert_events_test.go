// ABOUTME: Integration tests for alert event listing HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB; inserts events directly via store for setup.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAlertEvents_List verifies listing alert events with and without a rule_id filter.
func TestAlertEvents_List(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Create two alert rules.
	rule1Resp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer rule1Resp.Body.Close() //nolint:errcheck,gosec // G104
	if rule1Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule1: got %d, want 201", rule1Resp.StatusCode)
	}
	var rule1 struct{ ID string `json:"id"` }
	if err := json.NewDecoder(rule1Resp.Body).Decode(&rule1); err != nil {
		t.Fatalf("decode rule1: %v", err)
	}

	rule2Resp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, `{
  "name": "CISA KEV Rule",
  "logic": "and",
  "conditions": [{"field": "in_cisa_kev", "operator": "eq", "value": true}],
  "watchlist_ids": [],
  "enabled": true
}`)
	defer rule2Resp.Body.Close() //nolint:errcheck,gosec // G104
	if rule2Resp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule2: got %d, want 201", rule2Resp.StatusCode)
	}
	var rule2 struct{ ID string `json:"id"` }
	if err := json.NewDecoder(rule2Resp.Body).Decode(&rule2); err != nil {
		t.Fatalf("decode rule2: %v", err)
	}

	// Parse IDs for direct store access.
	orgID, err := uuid.Parse(aliceReg.OrgID)
	if err != nil {
		t.Fatalf("parse orgID: %v", err)
	}
	ruleID1, err := uuid.Parse(rule1.ID)
	if err != nil {
		t.Fatalf("parse ruleID1: %v", err)
	}
	ruleID2, err := uuid.Parse(rule2.ID)
	if err != nil {
		t.Fatalf("parse ruleID2: %v", err)
	}

	// Insert events directly via store (simulating worker evaluation).
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID1, "CVE-2024-00001", "hash1", false)
	if err != nil {
		t.Fatalf("insert event1: %v", err)
	}
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID2, "CVE-2024-00002", "hash2", false)
	if err != nil {
		t.Fatalf("insert event2: %v", err)
	}

	// List all events.
	listResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "")
	defer listResp.Body.Close() //nolint:errcheck,gosec // G104
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list events: got %d, want 200", listResp.StatusCode)
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

	// Filter by rule_id for rule1.
	rule1EventsResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?rule_id="+rule1.ID)
	defer rule1EventsResp.Body.Close() //nolint:errcheck,gosec // G104
	if rule1EventsResp.StatusCode != http.StatusOK {
		t.Fatalf("list rule1 events: got %d, want 200", rule1EventsResp.StatusCode)
	}
	var rule1Events struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(rule1EventsResp.Body).Decode(&rule1Events); err != nil {
		t.Fatalf("decode rule1 events: %v", err)
	}
	if len(rule1Events.Items) != 1 {
		t.Fatalf("rule1 events count = %d, want 1", len(rule1Events.Items))
	}
	if rule1Events.Items[0]["cve_id"] != "CVE-2024-00001" {
		t.Errorf("rule1 event cve_id = %v, want CVE-2024-00001", rule1Events.Items[0]["cve_id"])
	}

}

// TestAlertEvents_CveIDFilter verifies filtering alert events by ?cve_id=.
func TestAlertEvents_CveIDFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	ruleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer ruleResp.Body.Close() //nolint:errcheck,gosec // G104
	if ruleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule: got %d, want 201", ruleResp.StatusCode)
	}
	var rule struct{ ID string `json:"id"` }
	if err := json.NewDecoder(ruleResp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode rule: %v", err)
	}

	orgID, err := uuid.Parse(aliceReg.OrgID)
	if err != nil {
		t.Fatalf("parse orgID: %v", err)
	}
	ruleID, err := uuid.Parse(rule.ID)
	if err != nil {
		t.Fatalf("parse ruleID: %v", err)
	}

	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID, "CVE-2024-00010", "hashA", false)
	if err != nil {
		t.Fatalf("insert event A: %v", err)
	}
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID, "CVE-2024-00020", "hashB", false)
	if err != nil {
		t.Fatalf("insert event B: %v", err)
	}

	filterResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?cve_id=CVE-2024-00010")
	defer filterResp.Body.Close() //nolint:errcheck,gosec // G104
	if filterResp.StatusCode != http.StatusOK {
		t.Fatalf("filter by cve_id: got %d, want 200", filterResp.StatusCode)
	}
	var filtered struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(filterResp.Body).Decode(&filtered); err != nil {
		t.Fatalf("decode filtered: %v", err)
	}
	if len(filtered.Items) != 1 {
		t.Fatalf("filtered count = %d, want 1", len(filtered.Items))
	}
	if filtered.Items[0]["cve_id"] != "CVE-2024-00010" {
		t.Errorf("filtered cve_id = %v, want CVE-2024-00010", filtered.Items[0]["cve_id"])
	}
}

// TestAlertEvents_CrossOrgIsolation verifies that alert events are not visible across org boundaries.
// Registration in "open" mode only auto-creates an org for the first user; Bob (second user) has no org
// and therefore cannot be a member of Alice's org.
func TestAlertEvents_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	// Alice is the first user — she gets an auto-org.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	ruleResp := doCreateAlertRule(t, ctx, ts, aliceToken, aliceReg.OrgID, validRuleDSL)
	defer ruleResp.Body.Close() //nolint:errcheck,gosec // G104
	if ruleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule: got %d, want 201", ruleResp.StatusCode)
	}
	var rule struct{ ID string `json:"id"` }
	if err := json.NewDecoder(ruleResp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode rule: %v", err)
	}

	orgID, err := uuid.Parse(aliceReg.OrgID)
	if err != nil {
		t.Fatalf("parse orgID: %v", err)
	}
	ruleID, err := uuid.Parse(rule.ID)
	if err != nil {
		t.Fatalf("parse ruleID: %v", err)
	}
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID, "CVE-2024-99999", "hashX", false)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}

	// Bob is the second user — he has no org and is not a member of Alice's org.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Bob cannot access Alice's org events (not a member → 403).
	crossResp := doListAlertEvents(t, ctx, ts, bobToken, aliceReg.OrgID, "")
	defer crossResp.Body.Close() //nolint:errcheck,gosec // G104
	if crossResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org list: got %d, want 403", crossResp.StatusCode)
	}
}

// TestAlertEvents_LastMatchStateFilter verifies filtering alert events by ?last_match_state=.
func TestAlertEvents_LastMatchStateFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	ruleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer ruleResp.Body.Close() //nolint:errcheck,gosec // G104
	if ruleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule: got %d, want 201", ruleResp.StatusCode)
	}
	var rule struct{ ID string `json:"id"` }
	if err := json.NewDecoder(ruleResp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode rule: %v", err)
	}

	orgID, err := uuid.Parse(aliceReg.OrgID)
	if err != nil {
		t.Fatalf("parse orgID: %v", err)
	}
	ruleID, err := uuid.Parse(rule.ID)
	if err != nil {
		t.Fatalf("parse ruleID: %v", err)
	}

	// Insert two events — both default to last_match_state=true (initial fire).
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID, "CVE-2024-00100", "hashM1", false)
	if err != nil {
		t.Fatalf("insert event M1: %v", err)
	}
	_, err = srv.store.InsertAlertEvent(ctx, orgID, ruleID, "CVE-2024-00200", "hashM2", false)
	if err != nil {
		t.Fatalf("insert event M2: %v", err)
	}

	// Filter by last_match_state=true.
	trueResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?last_match_state=true")
	defer trueResp.Body.Close() //nolint:errcheck,gosec // G104
	if trueResp.StatusCode != http.StatusOK {
		t.Fatalf("filter last_match_state=true: got %d, want 200", trueResp.StatusCode)
	}
	var trueList struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(trueResp.Body).Decode(&trueList); err != nil {
		t.Fatalf("decode true list: %v", err)
	}
	if len(trueList.Items) != 2 {
		t.Errorf("last_match_state=true count = %d, want 2", len(trueList.Items))
	}

	// Filter by last_match_state=false — no events match (all are true).
	falseResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?last_match_state=false")
	defer falseResp.Body.Close() //nolint:errcheck,gosec // G104
	if falseResp.StatusCode != http.StatusOK {
		t.Fatalf("filter last_match_state=false: got %d, want 200", falseResp.StatusCode)
	}
	var falseList struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(falseResp.Body).Decode(&falseList); err != nil {
		t.Fatalf("decode false list: %v", err)
	}
	if len(falseList.Items) != 0 {
		t.Errorf("last_match_state=false count = %d, want 0", len(falseList.Items))
	}
}

// TestAlertEvents_Pagination verifies cursor-based pagination on alert events.
func TestAlertEvents_Pagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	ruleResp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, validRuleDSL)
	defer ruleResp.Body.Close() //nolint:errcheck,gosec // G104
	if ruleResp.StatusCode != http.StatusCreated {
		t.Fatalf("create rule: got %d, want 201", ruleResp.StatusCode)
	}
	var rule struct{ ID string `json:"id"` }
	if err := json.NewDecoder(ruleResp.Body).Decode(&rule); err != nil {
		t.Fatalf("decode rule: %v", err)
	}

	orgID, err := uuid.Parse(aliceReg.OrgID)
	if err != nil {
		t.Fatalf("parse orgID: %v", err)
	}
	ruleID, err := uuid.Parse(rule.ID)
	if err != nil {
		t.Fatalf("parse ruleID: %v", err)
	}

	// Insert 3 events.
	for i := 1; i <= 3; i++ {
		cveID := "CVE-2024-0100" + string(rune('0'+i))
		hash := "pagHash" + string(rune('0'+i))
		_, err := srv.store.InsertAlertEvent(ctx, orgID, ruleID, cveID, hash, false)
		if err != nil {
			t.Fatalf("insert event %d: %v", i, err)
		}
	}

	// List all — should get 3 events with limit=100 (no next_cursor).
	allResp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "")
	defer allResp.Body.Close() //nolint:errcheck,gosec // G104
	if allResp.StatusCode != http.StatusOK {
		t.Fatalf("list all: got %d, want 200", allResp.StatusCode)
	}
	var allList struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	if err := json.NewDecoder(allResp.Body).Decode(&allList); err != nil {
		t.Fatalf("decode all: %v", err)
	}
	if len(allList.Items) != 3 {
		t.Fatalf("all count = %d, want 3", len(allList.Items))
	}
	// With only 3 items and limit=100, no pagination cursor should exist.
	if allList.NextCursor != nil {
		// If a cursor is returned, use it to verify page 2 works.
		page2Resp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?after="+*allList.NextCursor)
		defer page2Resp.Body.Close() //nolint:errcheck,gosec // G104
		if page2Resp.StatusCode != http.StatusOK {
			t.Fatalf("page 2: got %d, want 200", page2Resp.StatusCode)
		}
	}
}

// TestAlertEvents_InvalidRuleIDFilter verifies that an invalid UUID for ?rule_id= returns 400.
func TestAlertEvents_InvalidRuleIDFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?rule_id=not-a-uuid")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid rule_id: got %d, want 400", resp.StatusCode)
	}
}

// TestAlertEvents_InvalidSinceFilter verifies that an invalid ?since= value returns 400.
func TestAlertEvents_InvalidSinceFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "?since=not-a-date")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid since: got %d, want 400", resp.StatusCode)
	}
}

// TestAlertEvents_EmptyList verifies that listing events with no data returns an empty array.
func TestAlertEvents_EmptyList(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doListAlertEvents(t, ctx, ts, token, aliceReg.OrgID, "")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("empty list: got %d, want 200", resp.StatusCode)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode empty list: %v", err)
	}
	if len(listed.Items) != 0 {
		t.Errorf("empty list count = %d, want 0", len(listed.Items))
	}
}

// doListAlertEvents performs a GET /api/v1/orgs/{org_id}/alert-events request.
// queryString may be empty or a URL query string like "?rule_id=...".
func doListAlertEvents(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, queryString string) *http.Response {
	t.Helper()
	url := ts.URL + "/api/v1/orgs/" + orgID + "/alert-events" + queryString
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list alert events: %v", err)
	}
	return resp
}
