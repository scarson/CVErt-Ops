// ABOUTME: Integration tests for store/notification_delivery.go — delivery job queue operations.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// mustUpsertDelivery is a test helper that calls UpsertDelivery or fatals.
func mustUpsertDelivery(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID, ruleID, chanID uuid.UUID, payload []byte, debounceSeconds int) {
	t.Helper()
	if err := s.UpsertDelivery(ctx, orgID, ruleID, chanID, payload, debounceSeconds); err != nil {
		t.Fatalf("UpsertDelivery: %v", err)
	}
}

// setupDeliveryFixture creates an org, alert rule, and notification channel for delivery tests.
// Returns orgID, ruleID, channelID.
func setupDeliveryFixture(t *testing.T, s *testutil.TestDB, ctx context.Context, orgSuffix string) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	org, _ := s.CreateOrg(ctx, "NDOrg"+orgSuffix)
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "NDRule"+orgSuffix)
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "NDChan"+orgSuffix)
	return org.ID, rule.ID, chanID
}

// countPendingDeliveries counts pending delivery rows for a (rule_id, channel_id) pair via raw SQL.
func countPendingDeliveries(t *testing.T, s *testutil.TestDB, ctx context.Context, ruleID, chanID uuid.UUID) int {
	t.Helper()
	var count int
	row := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		ruleID, chanID)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("countPendingDeliveries: %v", err)
	}
	return count
}

// getDeliveryStatus reads the status of a delivery row by ID via raw SQL.
func getDeliveryStatus(t *testing.T, s *testutil.TestDB, ctx context.Context, id uuid.UUID) string {
	t.Helper()
	var status string
	row := s.DB().QueryRowContext(ctx, `SELECT status FROM notification_deliveries WHERE id=$1`, id)
	if err := row.Scan(&status); err != nil {
		t.Fatalf("getDeliveryStatus(%v): %v", id, err)
	}
	return status
}

// getAttemptCount reads the attempt_count of a delivery row by ID via raw SQL.
func getAttemptCount(t *testing.T, s *testutil.TestDB, ctx context.Context, id uuid.UUID) int {
	t.Helper()
	var count int
	row := s.DB().QueryRowContext(ctx, `SELECT attempt_count FROM notification_deliveries WHERE id=$1`, id)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("getAttemptCount(%v): %v", id, err)
	}
	return count
}

// getPayloadLength returns the number of elements in the JSONB payload array for a delivery row.
func getPayloadLength(t *testing.T, s *testutil.TestDB, ctx context.Context, ruleID, chanID uuid.UUID) int {
	t.Helper()
	var raw []byte
	row := s.DB().QueryRowContext(ctx,
		`SELECT payload FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		ruleID, chanID)
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("getPayloadLength: %v", err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("getPayloadLength unmarshal: %v", err)
	}
	return len(items)
}

// claimAndMarkProcessing claims pending deliveries (which atomically marks them
// processing) and returns the IDs of the claimed deliveries.
func claimAndMarkProcessing(t *testing.T, s *testutil.TestDB, ctx context.Context) []uuid.UUID {
	t.Helper()
	claimed, err := s.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimPendingDeliveries: %v", err)
	}
	if len(claimed) == 0 {
		t.Fatal("expected at least 1 claimed delivery, got 0")
	}
	ids := make([]uuid.UUID, len(claimed))
	for i, c := range claimed {
		ids[i] = c.ID
	}
	return ids
}

func TestUpsertDelivery_CreatesThenDebounces(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "1")

	snapshot1 := []byte(`{"cve_id":"CVE-2024-0001"}`)
	snapshot2 := []byte(`{"cve_id":"CVE-2024-0002"}`)

	// First upsert: creates a new pending row.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, snapshot1, 0)

	count := countPendingDeliveries(t, s, ctx, ruleID, chanID)
	if count != 1 {
		t.Fatalf("after first upsert: got %d pending rows, want 1", count)
	}

	// Second upsert for the same rule+channel: must debounce into the same row.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, snapshot2, 0)

	count = countPendingDeliveries(t, s, ctx, ruleID, chanID)
	if count != 1 {
		t.Fatalf("after second upsert: got %d pending rows, want 1 (debounce)", count)
	}

	// Payload must contain both snapshots.
	payloadLen := getPayloadLength(t, s, ctx, ruleID, chanID)
	if payloadLen != 2 {
		t.Errorf("payload length = %d, want 2 (one per upsert)", payloadLen)
	}
}

func TestClaimPendingDeliveries_SkipsNotReady(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "2")

	// Upsert with a 120s debounce: send_after is in the future, should not be claimed.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0010"}`), 120)

	notReady, err := s.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimPendingDeliveries (not ready): %v", err)
	}
	if len(notReady) != 0 {
		t.Errorf("expected 0 claimed (debounce not expired), got %d", len(notReady))
	}

	// Set up a second fixture for the ready case (different rule+channel to avoid debounce conflict).
	orgID2, ruleID2, chanID2 := setupDeliveryFixture(t, s, ctx, "2b")
	mustUpsertDelivery(t, s, ctx, orgID2, ruleID2, chanID2, []byte(`{"cve_id":"CVE-2024-0011"}`), 0)

	ready, err := s.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimPendingDeliveries (ready): %v", err)
	}
	if len(ready) != 1 {
		t.Errorf("expected 1 claimed delivery, got %d", len(ready))
	}
	if ready[0].RuleID.UUID != ruleID2 {
		t.Errorf("claimed wrong delivery: ruleID=%v, want %v", ready[0].RuleID.UUID, ruleID2)
	}
	// Verify payload is present.
	if len(ready[0].Payload) == 0 {
		t.Error("claimed delivery has empty payload")
	}
}

func TestCompleteDelivery(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "3")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0020"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	if err := s.CompleteDelivery(ctx, ids[0]); err != nil {
		t.Fatalf("CompleteDelivery: %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "succeeded" {
		t.Errorf("status = %q, want succeeded", status)
	}
}

func TestRetryDelivery_IncreasesAttemptCount(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "4")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0030"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	if err := s.RetryDelivery(ctx, ids[0], 5, "connection refused"); err != nil {
		t.Fatalf("RetryDelivery: %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "pending" {
		t.Errorf("status = %q, want pending", status)
	}

	attempts := getAttemptCount(t, s, ctx, ids[0])
	if attempts != 1 {
		t.Errorf("attempt_count = %d, want 1", attempts)
	}
}

func TestExhaustDelivery_SetsFailed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "5")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0040"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	initialAttempts := getAttemptCount(t, s, ctx, ids[0])

	if err := s.ExhaustDelivery(ctx, ids[0], "max retries exceeded"); err != nil {
		t.Fatalf("ExhaustDelivery: %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "failed" {
		t.Errorf("status = %q, want failed", status)
	}

	attempts := getAttemptCount(t, s, ctx, ids[0])
	if attempts != initialAttempts+1 {
		t.Errorf("attempt_count = %d, want %d", attempts, initialAttempts+1)
	}
}

func TestResetStuckDeliveries(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "6")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0050"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "processing" {
		t.Fatalf("expected processing after mark, got %q", status)
	}

	// Reset with 0s threshold: any processing row updated before "now" qualifies.
	// We use time.Duration(0) which passes 0 seconds to the query.
	if err := s.ResetStuckDeliveries(ctx, 0); err != nil {
		t.Fatalf("ResetStuckDeliveries: %v", err)
	}

	status = getDeliveryStatus(t, s, ctx, ids[0])
	if status != "pending" {
		t.Errorf("status after reset = %q, want pending", status)
	}
}

func TestReplayDelivery_ResetsFailedToZero(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "7")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0060"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	// Exhaust the delivery to get it into status=failed.
	if err := s.ExhaustDelivery(ctx, ids[0], "permanent failure"); err != nil {
		t.Fatalf("ExhaustDelivery: %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "failed" {
		t.Fatalf("expected failed after exhaust, got %q", status)
	}

	// Replay: must reset to pending with attempt_count=0.
	if err := s.ReplayDelivery(ctx, ids[0], orgID); err != nil {
		t.Fatalf("ReplayDelivery: %v", err)
	}

	status = getDeliveryStatus(t, s, ctx, ids[0])
	if status != "pending" {
		t.Errorf("status after replay = %q, want pending", status)
	}

	attempts := getAttemptCount(t, s, ctx, ids[0])
	if attempts != 0 {
		t.Errorf("attempt_count after replay = %d, want 0", attempts)
	}
}

// insertAlertEventBackdated inserts an alert_event with a custom first_fired_at via
// raw SQL so that OrphanedAlertEvents (which checks first_fired_at < now() - 5 min)
// can see it in tests.
func insertAlertEventBackdated(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID, ruleID uuid.UUID, cveID string, backdateDuration time.Duration) {
	t.Helper()
	// RLS on alert_events requires app.org_id or bypass_rls. The superuser pool
	// in TestDB bypasses RLS via withBypassTx; for raw SQL we use the same
	// bypass_rls trick in a transaction.
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("insertAlertEventBackdated: begin tx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		t.Fatalf("insertAlertEventBackdated: set bypass_rls: %v", err)
	}
	// Use a unique material_hash per call to avoid UNIQUE constraint conflicts.
	materialHash := uuid.New().String()
	// Pass seconds as an integer to avoid Go duration string format incompatibility
	// with PostgreSQL interval parsing (e.g., "10m0s" is not accepted by Postgres).
	backdateSeconds := int(backdateDuration.Seconds())
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery, first_fired_at)
		VALUES ($1, $2, $3, $4, true, false, now() - ($5 * interval '1 second'))`,
		orgID, ruleID, cveID, materialHash, backdateSeconds,
	)
	if err != nil {
		t.Fatalf("insertAlertEventBackdated: insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("insertAlertEventBackdated: commit: %v", err)
	}
}

func TestOrphanedAlertEvents(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "8")

	// Insert an alert_event that fired 10 minutes ago (exceeds the 5-minute threshold).
	insertAlertEventBackdated(t, s, ctx, orgID, ruleID, "CVE-2024-0070", 10*time.Minute)

	// Without a delivery row, the event must appear in orphaned results.
	orphaned, err := s.OrphanedAlertEvents(ctx, 10)
	if err != nil {
		t.Fatalf("OrphanedAlertEvents (no delivery): %v", err)
	}
	found := false
	for _, row := range orphaned {
		if row.OrgID == orgID && row.RuleID == ruleID && row.CveID == "CVE-2024-0070" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2024-0070 in orphaned results, got %v", orphaned)
	}

	// Create a succeeded delivery row for the same rule+org to satisfy the orphan check.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0070"}`), 0)
	ids := claimAndMarkProcessing(t, s, ctx)
	if err := s.CompleteDelivery(ctx, ids[0]); err != nil {
		t.Fatalf("CompleteDelivery: %v", err)
	}

	// With a succeeded delivery row, the event must NOT appear in orphaned results.
	orphaned2, err := s.OrphanedAlertEvents(ctx, 10)
	if err != nil {
		t.Fatalf("OrphanedAlertEvents (with delivery): %v", err)
	}
	for _, row := range orphaned2 {
		if row.OrgID == orgID && row.RuleID == ruleID && row.CveID == "CVE-2024-0070" {
			t.Errorf("CVE-2024-0070 should not be in orphaned results after delivery exists")
		}
	}
}

func TestListDeliveries_FilterByStatus(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// One org; two independent rule+channel pairs so each UpsertDelivery gets its own row.
	orgID, ruleID1, chanID1 := setupDeliveryFixture(t, s, ctx, "9a")
	rule2 := mustCreateAlertRule(t, s, ctx, orgID, "NDRule9b")
	chanID2, _ := mustCreateNotificationChannel(t, s, ctx, orgID, "NDChan9b")
	ruleID2 := rule2.ID

	// Row 1: will be left as pending.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID1, chanID1, []byte(`{"cve_id":"CVE-2024-0080"}`), 0)
	// Row 2: will be claimed and completed → succeeded.
	mustUpsertDelivery(t, s, ctx, orgID, ruleID2, chanID2, []byte(`{"cve_id":"CVE-2024-0081"}`), 0)

	// Claim and complete only the second delivery.
	claimed, err := s.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimPendingDeliveries: %v", err)
	}
	// Find the one for ruleID2.
	var id2 uuid.UUID
	for _, c := range claimed {
		if c.RuleID.UUID == ruleID2 {
			id2 = c.ID
		}
	}
	if id2 == uuid.Nil {
		t.Fatal("could not find claimed delivery for ruleID2")
	}
	// ClaimPendingDeliveries already marked the row as processing.
	if err := s.CompleteDelivery(ctx, id2); err != nil {
		t.Fatalf("CompleteDelivery: %v", err)
	}

	// Keyset pagination sentinel: use a far-future cursor so all rows qualify.
	cursor := time.Now().Add(24 * time.Hour)

	// Filter by status=succeeded: only the completed row.
	succeeded, err := s.ListDeliveries(ctx, orgID, uuid.Nil, uuid.Nil, "succeeded", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(succeeded): %v", err)
	}
	if len(succeeded) != 1 {
		t.Errorf("ListDeliveries(succeeded): got %d rows, want 1", len(succeeded))
	}
	if len(succeeded) > 0 && succeeded[0].Status != "succeeded" {
		t.Errorf("ListDeliveries(succeeded): status = %q, want succeeded", succeeded[0].Status)
	}

	// No status filter: both rows returned.
	all, err := s.ListDeliveries(ctx, orgID, uuid.Nil, uuid.Nil, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(all): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("ListDeliveries(all): got %d rows, want 2", len(all))
	}
}

func TestGetDelivery(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "10")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-0090"}`), 0)

	// Retrieve the delivery ID via raw SQL.
	var id uuid.UUID
	row := s.DB().QueryRowContext(ctx,
		`SELECT id FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		ruleID, chanID)
	if err := row.Scan(&id); err != nil {
		t.Fatalf("scan delivery id: %v", err)
	}

	// GetDelivery with correct org must return the row.
	delivery, err := s.GetDelivery(ctx, id, orgID)
	if err != nil {
		t.Fatalf("GetDelivery: %v", err)
	}
	if delivery == nil {
		t.Fatal("GetDelivery returned nil for existing delivery")
	}
	if delivery.ID != id {
		t.Errorf("GetDelivery ID = %v, want %v", delivery.ID, id)
	}
	if delivery.RuleID.UUID != ruleID {
		t.Errorf("GetDelivery RuleID = %v, want %v", delivery.RuleID.UUID, ruleID)
	}

	// GetDelivery with a random UUID must return nil (not found).
	notFound, err := s.GetDelivery(ctx, uuid.New(), orgID)
	if err != nil {
		t.Fatalf("GetDelivery(not found): %v", err)
	}
	if notFound != nil {
		t.Error("GetDelivery with unknown ID should return nil")
	}
}

func TestListDeliveries_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID1, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "XO1a")
	org2, _ := s.CreateOrg(ctx, "NDOrgXO1b")
	orgID2 := org2.ID

	mustUpsertDelivery(t, s, ctx, orgID1, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-XO1"}`), 0)

	cursor := time.Now().Add(24 * time.Hour)

	// org1 sees its delivery.
	rows, err := s.ListDeliveries(ctx, orgID1, uuid.Nil, uuid.Nil, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(org1): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("org1 should see 1 delivery, got %d", len(rows))
	}

	// org2 must not see org1's deliveries.
	rows, err = s.ListDeliveries(ctx, orgID2, uuid.Nil, uuid.Nil, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(wrong org): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 deliveries for wrong org, got %d", len(rows))
	}
}

func TestGetDelivery_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID1, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "XO2a")
	org2, _ := s.CreateOrg(ctx, "NDOrgXO2b")
	orgID2 := org2.ID

	mustUpsertDelivery(t, s, ctx, orgID1, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-XO2"}`), 0)

	// Get delivery ID via raw SQL.
	var deliveryID uuid.UUID
	row := s.DB().QueryRowContext(ctx,
		`SELECT id FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		ruleID, chanID)
	if err := row.Scan(&deliveryID); err != nil {
		t.Fatalf("scan delivery id: %v", err)
	}

	// org1 sees its delivery.
	d, err := s.GetDelivery(ctx, deliveryID, orgID1)
	if err != nil {
		t.Fatalf("GetDelivery(org1): %v", err)
	}
	if d == nil {
		t.Fatal("GetDelivery(org1) returned nil for existing delivery")
	}

	// org2 must not see org1's delivery.
	d, err = s.GetDelivery(ctx, deliveryID, orgID2)
	if err != nil {
		t.Fatalf("GetDelivery(wrong org): %v", err)
	}
	if d != nil {
		t.Error("GetDelivery with wrong org should return nil")
	}
}

func TestReplayDelivery_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID1, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "XO3a")
	org2, _ := s.CreateOrg(ctx, "NDOrgXO3b")
	orgID2 := org2.ID

	mustUpsertDelivery(t, s, ctx, orgID1, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-XO3"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)
	if err := s.ExhaustDelivery(ctx, ids[0], "permanent failure"); err != nil {
		t.Fatalf("ExhaustDelivery: %v", err)
	}

	// org2 attempts to replay org1's delivery — should be a no-op.
	if err := s.ReplayDelivery(ctx, ids[0], orgID2); err != nil {
		t.Fatalf("ReplayDelivery(wrong org): %v", err)
	}

	// Delivery must still be failed (not replayed).
	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "failed" {
		t.Errorf("delivery should still be failed after cross-org replay, got %q", status)
	}

	// org1 can replay its own delivery.
	if err := s.ReplayDelivery(ctx, ids[0], orgID1); err != nil {
		t.Fatalf("ReplayDelivery(org1): %v", err)
	}
	status = getDeliveryStatus(t, s, ctx, ids[0])
	if status != "pending" {
		t.Errorf("status after org1 replay = %q, want pending", status)
	}
}

func TestReplayDelivery_NoOpFromPending(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "RPNoOp1")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-RPNOOP"}`), 0)

	// Get delivery ID.
	var deliveryID uuid.UUID
	row := s.DB().QueryRowContext(ctx,
		`SELECT id FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		ruleID, chanID)
	if err := row.Scan(&deliveryID); err != nil {
		t.Fatalf("scan delivery id: %v", err)
	}

	// Replay from pending status should be a no-op (SQL guard: WHERE status IN ('failed', 'cancelled')).
	if err := s.ReplayDelivery(ctx, deliveryID, orgID); err != nil {
		t.Fatalf("ReplayDelivery(pending): %v", err)
	}

	// Status should still be pending (unchanged).
	status := getDeliveryStatus(t, s, ctx, deliveryID)
	if status != "pending" {
		t.Errorf("status after replay from pending = %q, want pending", status)
	}
}

func TestReplayDelivery_NoOpFromSucceeded(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "RPNoOp2")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-RPNOOP2"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)
	if err := s.CompleteDelivery(ctx, ids[0]); err != nil {
		t.Fatalf("CompleteDelivery: %v", err)
	}

	// Replay from succeeded status should be a no-op.
	if err := s.ReplayDelivery(ctx, ids[0], orgID); err != nil {
		t.Fatalf("ReplayDelivery(succeeded): %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "succeeded" {
		t.Errorf("status after replay from succeeded = %q, want succeeded", status)
	}
}

func TestRetryDelivery_EmptyLastError(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "RetryEmpty")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-RETEMPTY"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	// Retry with empty lastError — should not error.
	if err := s.RetryDelivery(ctx, ids[0], 5, ""); err != nil {
		t.Fatalf("RetryDelivery(empty error): %v", err)
	}

	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "pending" {
		t.Errorf("status after retry = %q, want pending", status)
	}
}

func TestResetStuckDeliveries_RecentlyUpdatedSurvives(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "StuckRecent")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2024-STUCKRECENT"}`), 0)

	ids := claimAndMarkProcessing(t, s, ctx)

	// Reset with a 1-hour threshold: recently-updated rows should NOT be reset.
	if err := s.ResetStuckDeliveries(ctx, 1*time.Hour); err != nil {
		t.Fatalf("ResetStuckDeliveries(1h): %v", err)
	}

	// Should still be processing (not reset).
	status := getDeliveryStatus(t, s, ctx, ids[0])
	if status != "processing" {
		t.Errorf("recently-updated delivery should survive 1h reset, got %q", status)
	}
}

func TestListDeliveries_FilterByRuleAndChannel(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID1, chanID1 := setupDeliveryFixture(t, s, ctx, "FilterRC1")
	rule2 := mustCreateAlertRule(t, s, ctx, orgID, "FilterRule2")
	chanID2, _ := mustCreateNotificationChannel(t, s, ctx, orgID, "FilterChan2")

	mustUpsertDelivery(t, s, ctx, orgID, ruleID1, chanID1, []byte(`{"cve_id":"CVE-2024-F1"}`), 0)
	mustUpsertDelivery(t, s, ctx, orgID, rule2.ID, chanID2, []byte(`{"cve_id":"CVE-2024-F2"}`), 0)

	cursor := time.Now().Add(24 * time.Hour)

	// Filter by ruleID1: should return only the first delivery.
	byRule, err := s.ListDeliveries(ctx, orgID, ruleID1, uuid.Nil, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(by rule): %v", err)
	}
	if len(byRule) != 1 {
		t.Errorf("filter by ruleID1: got %d rows, want 1", len(byRule))
	}

	// Filter by chanID2: should return only the second delivery.
	byChan, err := s.ListDeliveries(ctx, orgID, uuid.Nil, chanID2, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(by channel): %v", err)
	}
	if len(byChan) != 1 {
		t.Errorf("filter by chanID2: got %d rows, want 1", len(byChan))
	}

	// Filter by both ruleID1 + chanID2: should return 0 (no match).
	byBoth, err := s.ListDeliveries(ctx, orgID, ruleID1, chanID2, "", cursor, uuid.Nil, 10)
	if err != nil {
		t.Fatalf("ListDeliveries(mismatched rule+channel): %v", err)
	}
	if len(byBoth) != 0 {
		t.Errorf("mismatched rule+channel filter: got %d rows, want 0", len(byBoth))
	}
}

func TestOrphanedAlertEvents_SuppressedAndNonMatchingExcluded(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, _ := setupDeliveryFixture(t, s, ctx, "OrphFilter")

	// Insert a suppressed event (suppress_delivery=true) backdated.
	tx, err := s.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, "SET LOCAL app.bypass_rls = 'on'"); err != nil {
		t.Fatalf("set bypass_rls: %v", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery, first_fired_at)
		VALUES ($1, $2, 'CVE-SUPPRESS-1', $3, true, true, now() - interval '15 minutes')`,
		orgID, ruleID, uuid.New().String())
	if err != nil {
		t.Fatalf("insert suppressed event: %v", err)
	}
	// Insert a non-matching event (last_match_state=false) backdated.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, last_match_state, suppress_delivery, first_fired_at)
		VALUES ($1, $2, 'CVE-NOMATCH-1', $3, false, false, now() - interval '15 minutes')`,
		orgID, ruleID, uuid.New().String())
	if err != nil {
		t.Fatalf("insert non-matching event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	orphaned, err := s.OrphanedAlertEvents(ctx, 10)
	if err != nil {
		t.Fatalf("OrphanedAlertEvents: %v", err)
	}

	for _, row := range orphaned {
		if row.CveID == "CVE-SUPPRESS-1" {
			t.Error("suppressed events should be excluded from orphaned results")
		}
		if row.CveID == "CVE-NOMATCH-1" {
			t.Error("non-matching events (last_match_state=false) should be excluded from orphaned results")
		}
	}
}

func TestInsertDigestDelivery(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "DigestDelivOrg")
	report := mustCreateScheduledReport(t, s, ctx, org.ID, "DigestReport")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "DigestChan")

	payload := json.RawMessage(`[{"cve_id":"CVE-2025-0001","severity":"HIGH"}]`)
	if err := s.InsertDigestDelivery(ctx, org.ID, report.ID, chanID, payload); err != nil {
		t.Fatalf("InsertDigestDelivery: %v", err)
	}

	// Verify a delivery row was created with kind='digest'.
	var kind, status string
	var reportID *uuid.UUID
	row := s.DB().QueryRowContext(ctx,
		`SELECT kind, status, report_id FROM notification_deliveries WHERE channel_id=$1 AND report_id=$2`,
		chanID, report.ID)
	if err := row.Scan(&kind, &status, &reportID); err != nil {
		t.Fatalf("scan digest delivery row: %v", err)
	}
	if kind != "digest" {
		t.Errorf("kind = %q, want digest", kind)
	}
	if status != "pending" {
		t.Errorf("status = %q, want pending", status)
	}
	if reportID == nil || *reportID != report.ID {
		t.Errorf("report_id = %v, want %v", reportID, report.ID)
	}

	// Idempotent: second insert for same report+channel should not error (ON CONFLICT DO NOTHING).
	if err := s.InsertDigestDelivery(ctx, org.ID, report.ID, chanID, payload); err != nil {
		t.Fatalf("InsertDigestDelivery (idempotent): %v", err)
	}

	// Should still be exactly one row.
	var count int
	countRow := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_deliveries WHERE channel_id=$1 AND report_id=$2`,
		chanID, report.ID)
	if err := countRow.Scan(&count); err != nil {
		t.Fatalf("count digest deliveries: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 digest delivery row (idempotent), got %d", count)
	}
}

func TestDigestCVEs(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	db := s.DB()

	// Insert CVEs with different severities and timestamps.
	since := time.Now().Add(-1 * time.Hour)

	// CVE-2025-D001: critical, modified recently — should match.
	_, err := db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, cvss_v3_score, material_hash, date_modified_canonical)
		VALUES ($1, 'published', 'critical', 'Critical vuln', 9.8, $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET
			severity = EXCLUDED.severity,
			date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-D001", uuid.New().String(), time.Now())
	if err != nil {
		t.Fatalf("insert CVE-2025-D001: %v", err)
	}

	// CVE-2025-D002: low, modified recently — should match only without severity filter.
	_, err = db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, cvss_v3_score, material_hash, date_modified_canonical)
		VALUES ($1, 'published', 'low', 'Low vuln', 2.0, $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET
			severity = EXCLUDED.severity,
			date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-D002", uuid.New().String(), time.Now())
	if err != nil {
		t.Fatalf("insert CVE-2025-D002: %v", err)
	}

	// CVE-2025-D003: critical but old — should NOT match (before since).
	_, err = db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, cvss_v3_score, material_hash, date_modified_canonical)
		VALUES ($1, 'published', 'critical', 'Old critical vuln', 9.5, $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET
			severity = EXCLUDED.severity,
			date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-D003", uuid.New().String(), time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("insert CVE-2025-D003: %v", err)
	}

	// Test 1: No severity filter — should return D001 and D002 (not D003, too old).
	all, err := s.DigestCVEs(ctx, since, nil)
	if err != nil {
		t.Fatalf("DigestCVEs(all): %v", err)
	}
	foundD001, foundD002, foundD003 := false, false, false
	for _, row := range all {
		switch row.CveID {
		case "CVE-2025-D001":
			foundD001 = true
		case "CVE-2025-D002":
			foundD002 = true
		case "CVE-2025-D003":
			foundD003 = true
		}
	}
	if !foundD001 {
		t.Error("DigestCVEs(all): expected CVE-2025-D001")
	}
	if !foundD002 {
		t.Error("DigestCVEs(all): expected CVE-2025-D002")
	}
	if foundD003 {
		t.Error("DigestCVEs(all): should not include CVE-2025-D003 (too old)")
	}

	// Test 2: Severity filter [critical, high] — only D001 should match.
	filtered, err := s.DigestCVEs(ctx, since, []string{"critical", "high"})
	if err != nil {
		t.Fatalf("DigestCVEs(critical,high): %v", err)
	}
	for _, row := range filtered {
		if row.CveID == "CVE-2025-D002" {
			t.Error("DigestCVEs(critical,high): should not include low-severity CVE-2025-D002")
		}
	}
	foundD001 = false
	for _, row := range filtered {
		if row.CveID == "CVE-2025-D001" {
			foundD001 = true
		}
	}
	if !foundD001 {
		t.Error("DigestCVEs(critical,high): expected CVE-2025-D001")
	}
}

func TestDigestCVEs_ExcludesRejectedAndWithdrawn(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	db := s.DB()
	since := time.Now().Add(-1 * time.Hour)

	// Rejected CVE — must be excluded.
	_, err := db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, material_hash, date_modified_canonical)
		VALUES ($1, 'rejected', 'critical', 'Rejected vuln', $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET status = EXCLUDED.status, date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-REJ1", uuid.New().String(), time.Now())
	if err != nil {
		t.Fatalf("insert rejected CVE: %v", err)
	}

	// Withdrawn CVE — must be excluded.
	_, err = db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, material_hash, date_modified_canonical)
		VALUES ($1, 'withdrawn', 'high', 'Withdrawn vuln', $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET status = EXCLUDED.status, date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-WITH1", uuid.New().String(), time.Now())
	if err != nil {
		t.Fatalf("insert withdrawn CVE: %v", err)
	}

	// Published CVE — should be included as control.
	_, err = db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, status, severity, description_primary, material_hash, date_modified_canonical)
		VALUES ($1, 'published', 'critical', 'Published vuln', $2, $3)
		ON CONFLICT (cve_id) DO UPDATE SET status = EXCLUDED.status, date_modified_canonical = EXCLUDED.date_modified_canonical`,
		"CVE-2025-PUB1", uuid.New().String(), time.Now())
	if err != nil {
		t.Fatalf("insert published CVE: %v", err)
	}

	rows, err := s.DigestCVEs(ctx, since, nil)
	if err != nil {
		t.Fatalf("DigestCVEs: %v", err)
	}

	foundRejected, foundWithdrawn, foundPublished := false, false, false
	for _, row := range rows {
		switch row.CveID {
		case "CVE-2025-REJ1":
			foundRejected = true
		case "CVE-2025-WITH1":
			foundWithdrawn = true
		case "CVE-2025-PUB1":
			foundPublished = true
		}
	}
	if foundRejected {
		t.Error("rejected CVE should be excluded from DigestCVEs")
	}
	if foundWithdrawn {
		t.Error("withdrawn CVE should be excluded from DigestCVEs")
	}
	if !foundPublished {
		t.Error("published CVE should be included in DigestCVEs")
	}
}

func TestDigestCVEs_SortOrder(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	db := s.DB()
	since := time.Now().Add(-1 * time.Hour)

	// Insert CVEs with different severities to verify sort order:
	// critical > high > medium > low, with CVSS v3 tiebreaker.
	cves := []struct {
		id       string
		severity string
		cvss     float64
	}{
		{"CVE-2025-SORT-LOW", "low", 2.0},
		{"CVE-2025-SORT-MED", "medium", 5.0},
		{"CVE-2025-SORT-CRIT1", "critical", 9.0},
		{"CVE-2025-SORT-CRIT2", "critical", 10.0},
		{"CVE-2025-SORT-HIGH", "high", 7.5},
	}
	for _, c := range cves {
		_, err := db.ExecContext(ctx, `
			INSERT INTO cves (cve_id, status, severity, description_primary, cvss_v3_score, material_hash, date_modified_canonical)
			VALUES ($1, 'published', $2, 'Sort test', $3, $4, $5)
			ON CONFLICT (cve_id) DO UPDATE SET
				severity = EXCLUDED.severity,
				cvss_v3_score = EXCLUDED.cvss_v3_score,
				date_modified_canonical = EXCLUDED.date_modified_canonical`,
			c.id, c.severity, c.cvss, uuid.New().String(), time.Now())
		if err != nil {
			t.Fatalf("insert %s: %v", c.id, err)
		}
	}

	rows, err := s.DigestCVEs(ctx, since, nil)
	if err != nil {
		t.Fatalf("DigestCVEs: %v", err)
	}

	// Extract just the sort-test CVEs in order.
	var sortIDs []string
	for _, row := range rows {
		for _, c := range cves {
			if row.CveID == c.id {
				sortIDs = append(sortIDs, row.CveID)
			}
		}
	}

	// Expected order: CRIT2 (10.0) > CRIT1 (9.0) > HIGH (7.5) > MED (5.0) > LOW (2.0)
	expected := []string{
		"CVE-2025-SORT-CRIT2",
		"CVE-2025-SORT-CRIT1",
		"CVE-2025-SORT-HIGH",
		"CVE-2025-SORT-MED",
		"CVE-2025-SORT-LOW",
	}
	if len(sortIDs) != len(expected) {
		t.Fatalf("expected %d sort-test CVEs, got %d: %v", len(expected), len(sortIDs), sortIDs)
	}
	for i, id := range sortIDs {
		if id != expected[i] {
			t.Errorf("position %d: got %s, want %s", i, id, expected[i])
		}
	}
}
