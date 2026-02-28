// ABOUTME: Integration tests for store/notification_delivery.go — delivery job queue operations.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"

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

// claimAndMarkProcessing is a helper that claims pending deliveries and marks them processing.
// Returns the IDs of the claimed deliveries.
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
	if err := s.MarkDeliveriesProcessing(ctx, ids); err != nil {
		t.Fatalf("MarkDeliveriesProcessing: %v", err)
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
	if ready[0].RuleID != ruleID2 {
		t.Errorf("claimed wrong delivery: ruleID=%v, want %v", ready[0].RuleID, ruleID2)
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
