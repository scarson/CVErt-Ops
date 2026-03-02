// ABOUTME: Integration tests for delivery list, detail, and replay HTTP handlers.
// ABOUTME: Uses real Postgres via testutil.NewTestDB; creates delivery rows directly via store.
package api

import (
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
