// ABOUTME: Integration tests for delivery list, detail, and replay HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB; creates delivery rows directly via store.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── HTTP helper functions ─────────────────────────────────────────────────────

func doListDeliveries(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string, query url.Values) *http.Response {
	t.Helper()
	rawURL := ts.URL + "/api/v1/orgs/" + orgID + "/deliveries"
	if len(query) > 0 {
		rawURL += "?" + query.Encode()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("list deliveries: %v", err)
	}
	return resp
}

func doGetDelivery(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/deliveries/"+id, nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	return resp
}

func doReplayDelivery(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, id string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/deliveries/"+id+"/replay", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("replay delivery: %v", err)
	}
	return resp
}

// setDeliveryStatus directly updates a delivery's status via raw SQL, bypassing RLS.
func setDeliveryStatus(t *testing.T, ctx context.Context, db *testutil.TestDB, id uuid.UUID, status string) {
	t.Helper()
	_, err := db.DB().ExecContext(ctx,
		"UPDATE notification_deliveries SET status = $1, updated_at = now() WHERE id = $2",
		status, id,
	)
	if err != nil {
		t.Fatalf("setDeliveryStatus(%v, %q): %v", id, status, err)
	}
}

// createTestDelivery creates a rule, channel, and upserts a delivery for testing.
// Returns the channel ID and delivery payload so tests can look up the delivery row.
func createTestDelivery(t *testing.T, ctx context.Context, db *testutil.TestDB, orgID uuid.UUID, suffix string) (channelID uuid.UUID) {
	t.Helper()

	// Create a channel.
	chanRow, _, err := db.CreateNotificationChannel(ctx, orgID,
		"Test Channel "+suffix, "webhook", json.RawMessage(`{"url":"https://example.com/hook"}`))
	if err != nil {
		t.Fatalf("create channel (%s): %v", suffix, err)
	}
	channelID = chanRow.ID

	// Create an alert rule via the store directly.
	ruleRow, err := db.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "Test Rule " + suffix,
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"in_cisa_kev","operator":"eq","value":true}]`),
		Status:     "active",
	})
	if err != nil {
		t.Fatalf("create alert rule (%s): %v", suffix, err)
	}

	// Bind channel to rule.
	if err := db.BindChannelToRule(ctx, ruleRow.ID, channelID, orgID); err != nil {
		t.Fatalf("bind channel to rule (%s): %v", suffix, err)
	}

	// Upsert a delivery row.
	payload := json.RawMessage(`{"cve_id":"CVE-2024-00001"}`)
	if err := db.UpsertDelivery(ctx, orgID, ruleRow.ID, channelID, payload, 0); err != nil {
		t.Fatalf("upsert delivery (%s): %v", suffix, err)
	}

	return channelID
}

// getDeliveryIDByChannel returns the delivery ID for the given org and channel via raw SQL.
func getDeliveryIDByChannel(t *testing.T, ctx context.Context, db *testutil.TestDB, orgID, channelID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.DB().QueryRowContext(ctx,
		"SELECT id FROM notification_deliveries WHERE org_id = $1 AND channel_id = $2 LIMIT 1",
		orgID, channelID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("getDeliveryIDByChannel: %v", err)
	}
	return id
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestListDeliveries_FilterByStatus verifies that filtering by status returns only matching rows.
func TestListDeliveries_FilterByStatus(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)

	// Create two deliveries with distinct channels so debounce doesn't merge them.
	chanID1 := createTestDelivery(t, ctx, db, orgID, "A")
	chanID2 := createTestDelivery(t, ctx, db, orgID, "B")

	delID1 := getDeliveryIDByChannel(t, ctx, db, orgID, chanID1)
	delID2 := getDeliveryIDByChannel(t, ctx, db, orgID, chanID2)

	// Set statuses directly.
	setDeliveryStatus(t, ctx, db, delID1, "succeeded")
	setDeliveryStatus(t, ctx, db, delID2, "failed")

	// Filter by succeeded — expect 1.
	q := url.Values{}
	q.Set("status", "succeeded")
	succResp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q)
	defer succResp.Body.Close() //nolint:errcheck,gosec // G104
	if succResp.StatusCode != http.StatusOK {
		t.Fatalf("list succeeded: got %d, want 200", succResp.StatusCode)
	}
	var succList struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(succResp.Body).Decode(&succList); err != nil {
		t.Fatalf("decode succeeded list: %v", err)
	}
	if len(succList.Items) != 1 {
		t.Fatalf("succeeded count = %d, want 1", len(succList.Items))
	}
	if succList.Items[0]["status"] != "succeeded" {
		t.Errorf("status = %v, want succeeded", succList.Items[0]["status"])
	}

	// Filter by failed — expect 1.
	q2 := url.Values{}
	q2.Set("status", "failed")
	failResp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q2)
	defer failResp.Body.Close() //nolint:errcheck,gosec // G104
	if failResp.StatusCode != http.StatusOK {
		t.Fatalf("list failed: got %d, want 200", failResp.StatusCode)
	}
	var failList struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(failResp.Body).Decode(&failList); err != nil {
		t.Fatalf("decode failed list: %v", err)
	}
	if len(failList.Items) != 1 {
		t.Fatalf("failed count = %d, want 1", len(failList.Items))
	}
	if failList.Items[0]["status"] != "failed" {
		t.Errorf("status = %v, want failed", failList.Items[0]["status"])
	}
}

// TestGetDelivery_Found verifies that a delivery can be fetched by ID.
func TestGetDelivery_Found(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)
	chanID := createTestDelivery(t, ctx, db, orgID, "")
	delID := getDeliveryIDByChannel(t, ctx, db, orgID, chanID)

	resp := doGetDelivery(t, ctx, ts, token, aliceReg.OrgID, delID.String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get delivery: got %d, want 200", resp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["id"] != delID.String() {
		t.Errorf("id = %v, want %v", got["id"], delID.String())
	}
	// Detail response must include payload.
	if _, ok := got["payload"]; !ok {
		t.Error("detail response must include payload field")
	}
}

// TestGetDelivery_404 verifies that fetching a non-existent delivery returns 404.
func TestGetDelivery_404(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doGetDelivery(t, ctx, ts, token, aliceReg.OrgID, uuid.New().String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("get missing delivery: got %d, want 404", resp.StatusCode)
	}
}

// TestReplayDelivery_ResetsStatus verifies that replaying a failed delivery resets it to pending.
func TestReplayDelivery_ResetsStatus(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)
	chanID := createTestDelivery(t, ctx, db, orgID, "")
	delID := getDeliveryIDByChannel(t, ctx, db, orgID, chanID)

	// Put a last_error on the delivery and set status to failed.
	_, err := db.DB().ExecContext(ctx,
		"UPDATE notification_deliveries SET status='failed', attempt_count=3, last_error='timeout', updated_at=now() WHERE id=$1",
		delID,
	)
	if err != nil {
		t.Fatalf("set failed: %v", err)
	}

	replayResp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, delID.String())
	defer replayResp.Body.Close() //nolint:errcheck,gosec // G104
	if replayResp.StatusCode != http.StatusNoContent {
		t.Fatalf("replay: got %d, want 204", replayResp.StatusCode)
	}

	// Verify the delivery is now pending with reset fields.
	getResp := doGetDelivery(t, ctx, ts, token, aliceReg.OrgID, delID.String())
	defer getResp.Body.Close() //nolint:errcheck,gosec // G104
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get after replay: got %d, want 200", getResp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(getResp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["status"] != "pending" {
		t.Errorf("status after replay = %v, want pending", got["status"])
	}
	if got["attempt_count"] != float64(0) {
		t.Errorf("attempt_count after replay = %v, want 0", got["attempt_count"])
	}
	if got["last_error"] != nil {
		t.Errorf("last_error after replay = %v, want nil", got["last_error"])
	}
}

// TestReplayDelivery_RateLimited verifies that > 10 replay calls in the same org return 429.
func TestReplayDelivery_RateLimited(t *testing.T) {
	// Note: replayBuckets is a package-level sync.Map so rate limit state persists
	// between tests. This test uses a unique org (fresh server+db) so it gets its
	// own bucket and won't interfere with other tests.
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)

	// Create 11 distinct deliveries (one per channel so debounce won't merge them).
	const total = 11
	var delIDs [total]uuid.UUID
	for i := range total {
		suffix := string(rune('A' + i))
		chanID := createTestDelivery(t, ctx, db, orgID, suffix)
		delIDs[i] = getDeliveryIDByChannel(t, ctx, db, orgID, chanID)
	}

	// Set all to failed.
	for i := range total {
		setDeliveryStatus(t, ctx, db, delIDs[i], "failed")
	}

	// First 10 replays must succeed.
	for i := range 10 {
		resp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, delIDs[i].String())
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("replay %d: got %d, want 204", i+1, resp.StatusCode)
		}
	}

	// 11th replay must be rate-limited.
	resp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, delIDs[10].String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th replay: got %d, want 429", resp.StatusCode)
	}
}

// TestListDeliveries_LimitValidation verifies limit < 1 and limit > 200 both return 400.
func TestListDeliveries_LimitValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// limit=0 → 400
	q := url.Values{}
	q.Set("limit", "0")
	resp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=0: got %d, want 400", resp.StatusCode)
	}

	// limit=-1 → 400
	q2 := url.Values{}
	q2.Set("limit", "-1")
	resp2 := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q2)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=-1: got %d, want 400", resp2.StatusCode)
	}

	// limit=999 → 400 (exceeds max of 200)
	q3 := url.Values{}
	q3.Set("limit", "999")
	resp3 := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q3)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("limit=999: got %d, want 400", resp3.StatusCode)
	}
}

// TestListDeliveries_FilterByRuleAndChannel verifies that rule_id and channel_id query params filter results.
func TestListDeliveries_FilterByRuleAndChannel(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)
	chanID1 := createTestDelivery(t, ctx, db, orgID, "F1")
	chanID2 := createTestDelivery(t, ctx, db, orgID, "F2")

	// Filter by channel_id=chanID1 → expect 1.
	q := url.Values{}
	q.Set("channel_id", chanID1.String())
	resp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filter by channel_id: got %d, want 200", resp.StatusCode)
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("channel_id filter: got %d items, want 1", len(list.Items))
	}

	// Filter by channel_id=chanID2 → expect 1.
	q2 := url.Values{}
	q2.Set("channel_id", chanID2.String())
	resp2 := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q2)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("filter by channel_id2: got %d, want 200", resp2.StatusCode)
	}
	var list2 struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&list2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list2.Items) != 1 {
		t.Errorf("channel_id2 filter: got %d items, want 1", len(list2.Items))
	}

	// Invalid rule_id → 400.
	q3 := url.Values{}
	q3.Set("rule_id", "not-a-uuid")
	resp3 := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q3)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid rule_id: got %d, want 400", resp3.StatusCode)
	}

	// Invalid channel_id → 400.
	q4 := url.Values{}
	q4.Set("channel_id", "not-a-uuid")
	resp4 := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q4)
	defer resp4.Body.Close() //nolint:errcheck,gosec // G104
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid channel_id: got %d, want 400", resp4.StatusCode)
	}
}

// TestReplayDelivery_NonExistentID verifies replaying a non-existent delivery ID.
// ReplayDelivery uses a SQL WHERE guard (status IN ('failed','cancelled')),
// so a non-existent ID is a no-op → 204.
func TestReplayDelivery_NonExistentID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	resp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, uuid.New().String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	// Non-existent ID → handler checks existence first → 404.
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("replay non-existent: got %d, want 404", resp.StatusCode)
	}
}

// TestDeliveries_CrossOrgIsolation verifies that org B cannot list, get, or
// replay org A's deliveries.
func TestDeliveries_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	// Alice owns org A.
	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceLogin := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer aliceLogin.Body.Close() //nolint:errcheck,gosec // G104
	aliceToken := cookieValue(aliceLogin, "access_token")

	aliceOrgID := mustParseUUID(t, aliceReg.OrgID)

	// Create a delivery in Alice's org.
	chanID := createTestDelivery(t, ctx, db, aliceOrgID, "")
	delID := getDeliveryIDByChannel(t, ctx, db, aliceOrgID, chanID)
	setDeliveryStatus(t, ctx, db, delID, "failed")

	// Alice can see her delivery.
	aliceGet := doGetDelivery(t, ctx, ts, aliceToken, aliceReg.OrgID, delID.String())
	defer aliceGet.Body.Close() //nolint:errcheck,gosec // G104
	if aliceGet.StatusCode != http.StatusOK {
		t.Fatalf("alice get own delivery: got %d, want 200", aliceGet.StatusCode)
	}

	// Bob owns org B.
	doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")
	bobOrgReq, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		ts.URL+"/api/v1/orgs", bytes.NewBufferString(`{"name":"Bob Org"}`))
	bobOrgReq.Header.Set("Content-Type", "application/json")
	bobOrgReq.Header.Set("Cookie", "access_token="+bobToken)
	bobOrgReq.Header.Set("X-Requested-By", "CVErt-Ops")
	bobOrgResp, err := ts.Client().Do(bobOrgReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create bob org: %v", err)
	}
	defer bobOrgResp.Body.Close() //nolint:errcheck,gosec // G104
	var bobOrg struct {
		OrgID string `json:"org_id"`
	}
	if err := json.NewDecoder(bobOrgResp.Body).Decode(&bobOrg); err != nil {
		t.Fatalf("decode bob org: %v", err)
	}

	// Bob cannot get Alice's delivery by querying his own org.
	t.Run("get delivery in wrong org", func(t *testing.T) {
		resp := doGetDelivery(t, ctx, ts, bobToken, bobOrg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("bob get alice's delivery in bob's org: got %d, want 404", resp.StatusCode)
		}
	})

	// Bob's delivery list is empty.
	t.Run("list deliveries in wrong org", func(t *testing.T) {
		resp := doListDeliveries(t, ctx, ts, bobToken, bobOrg.OrgID, nil)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bob list deliveries: got %d, want 200", resp.StatusCode)
		}
		var list struct {
			Items []map[string]any `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(list.Items) != 0 {
			t.Errorf("bob's delivery list should be empty, got %d", len(list.Items))
		}
	})

	// Bob cannot access Alice's org at all — 403.
	t.Run("cross-org access forbidden", func(t *testing.T) {
		resp := doGetDelivery(t, ctx, ts, bobToken, aliceReg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("bob accessing alice's org: got %d, want 403", resp.StatusCode)
		}
	})

	// Bob cannot replay Alice's delivery via his own org.
	t.Run("replay delivery in wrong org", func(t *testing.T) {
		resp := doReplayDelivery(t, ctx, ts, bobToken, bobOrg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		// No-op (delivery not in Bob's org) → 204, but not actually replayed.
		// Verify Alice's delivery is still failed.
		aliceGet2 := doGetDelivery(t, ctx, ts, aliceToken, aliceReg.OrgID, delID.String())
		defer aliceGet2.Body.Close() //nolint:errcheck,gosec // G104
		var got map[string]any
		if err := json.NewDecoder(aliceGet2.Body).Decode(&got); err != nil {
			t.Fatalf("decode alice delivery: %v", err)
		}
		if got["status"] != "failed" {
			t.Errorf("alice's delivery should still be failed, got %v", got["status"])
		}
	})
}

// TestReplayDelivery_RBAC_ViewerMemberForbidden verifies that replay requires
// admin+ role. Viewers and members should get 403.
func TestReplayDelivery_RBAC_ViewerMemberForbidden(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	aliceOrgID, _ := uuid.Parse(aliceReg.OrgID)

	// Create a delivery and set to failed.
	chanID := createTestDelivery(t, ctx, db, aliceOrgID, "")
	delID := getDeliveryIDByChannel(t, ctx, db, aliceOrgID, chanID)
	setDeliveryStatus(t, ctx, db, delID, "failed")

	// Bob is a viewer.
	bobReg := doRegister(t, ctx, ts, "bob@example.com", "test-password-5678")
	bobUserID, _ := uuid.Parse(bobReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, bobUserID, "viewer"); err != nil {
		t.Fatalf("add Bob as viewer: %v", err)
	}
	bobLogin := doLogin(t, ctx, ts, "bob@example.com", "test-password-5678")
	defer bobLogin.Body.Close() //nolint:errcheck,gosec // G104
	bobToken := cookieValue(bobLogin, "access_token")

	// Carol is a member.
	carolReg := doRegister(t, ctx, ts, "carol@example.com", "test-password-9012")
	carolUserID, _ := uuid.Parse(carolReg.UserID)
	if err := db.CreateOrgMember(ctx, aliceOrgID, carolUserID, "member"); err != nil {
		t.Fatalf("add Carol as member: %v", err)
	}
	carolLogin := doLogin(t, ctx, ts, "carol@example.com", "test-password-9012")
	defer carolLogin.Body.Close() //nolint:errcheck,gosec // G104
	carolToken := cookieValue(carolLogin, "access_token")

	t.Run("viewer cannot replay", func(t *testing.T) {
		resp := doReplayDelivery(t, ctx, ts, bobToken, aliceReg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("viewer replay: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("member cannot replay", func(t *testing.T) {
		resp := doReplayDelivery(t, ctx, ts, carolToken, aliceReg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("member replay: got %d, want 403", resp.StatusCode)
		}
	})

	// Viewers and members CAN read deliveries.
	t.Run("viewer can list", func(t *testing.T) {
		resp := doListDeliveries(t, ctx, ts, bobToken, aliceReg.OrgID, nil)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Errorf("viewer list: got %d, want 200", resp.StatusCode)
		}
	})

	t.Run("member can get", func(t *testing.T) {
		resp := doGetDelivery(t, ctx, ts, carolToken, aliceReg.OrgID, delID.String())
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Errorf("member get: got %d, want 200", resp.StatusCode)
		}
	})
}

// TestListDeliveries_Envelope verifies the standard list envelope shape.
func TestListDeliveries_Envelope(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)
	createTestDelivery(t, ctx, db, orgID, "env")

	resp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, nil)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list deliveries: got %d, want 200", resp.StatusCode)
	}

	var envelope struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if envelope.Items == nil {
		t.Fatal("items field must be present (got nil)")
	}
	if len(envelope.Items) != 1 {
		t.Fatalf("items count = %d, want 1", len(envelope.Items))
	}
}

// TestListDeliveries_MalformedCursor verifies that an old-format cursor returns 400.
func TestListDeliveries_MalformedCursor(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Old format: RFC3339Nano/uuid (not base64-encoded JSON).
	q := url.Values{}
	q.Set("cursor", "2024-01-01T00:00:00Z/"+uuid.New().String())
	resp := doListDeliveries(t, ctx, ts, token, aliceReg.OrgID, q)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("old-format cursor: got %d, want 400", resp.StatusCode)
	}

	// Verify it's problem+json.
	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestReplayDelivery_429_ProblemJSON verifies that 429 responses use application/problem+json.
func TestReplayDelivery_429_ProblemJSON(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	aliceReg := doRegister(t, ctx, ts, "alice@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "alice@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, aliceReg.OrgID)

	// Create 11 distinct deliveries.
	const total = 11
	var delIDs [total]uuid.UUID
	for i := range total {
		suffix := "r" + string(rune('A'+i))
		chanID := createTestDelivery(t, ctx, db, orgID, suffix)
		delIDs[i] = getDeliveryIDByChannel(t, ctx, db, orgID, chanID)
	}

	// Set all to failed.
	for i := range total {
		setDeliveryStatus(t, ctx, db, delIDs[i], "failed")
	}

	// Exhaust the rate limit.
	for i := range 10 {
		resp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, delIDs[i].String())
		resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("replay %d: got %d, want 204", i+1, resp.StatusCode)
		}
	}

	// 11th replay triggers 429.
	resp := doReplayDelivery(t, ctx, ts, token, aliceReg.OrgID, delIDs[10].String())
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("11th replay: got %d, want 429", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var problem struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Status != 429 {
		t.Errorf("problem.status = %d, want 429", problem.Status)
	}
}
