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

	"github.com/scarson/cvert-ops/internal/store"
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
	if rule1Resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create rule1: got %d, want 202", rule1Resp.StatusCode)
	}
	var rule1 struct{ ID string `json:"id"` }
	if err := json.NewDecoder(rule1Resp.Body).Decode(&rule1); err != nil {
		t.Fatalf("decode rule1: %v", err)
	}

	rule2Resp := doCreateAlertRule(t, ctx, ts, token, aliceReg.OrgID, `{
  "name": "CISA KEV Rule",
  "logic": "and",
  "conditions": [{"field": "in_cisa_kev", "operator": "eq", "value": true}],
  "watchlist_ids": []
}`)
	defer rule2Resp.Body.Close() //nolint:errcheck,gosec // G104
	if rule2Resp.StatusCode != http.StatusAccepted {
		t.Fatalf("create rule2: got %d, want 202", rule2Resp.StatusCode)
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

	_ = ruleID2 // used in event insertion above
	_ = store.ListAlertEventsParams{} // ensure store import is used
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
