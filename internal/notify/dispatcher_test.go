// ABOUTME: Integration tests for Dispatcher.Fanout — CVE snapshot delivery row creation and debounce.
// ABOUTME: Uses testutil.NewTestDB; each test runs against a real Postgres testcontainer.
package notify_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/notify"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// countPendingDeliveries counts pending delivery rows for a (rule_id, channel_id) pair.
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

func TestFanout_NoChannels_NoOp(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "FanoutNoChOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FanoutNoChRule")

	// No channels bound to this rule — Fanout must return nil and create 0 delivery rows.
	d := notify.NewDispatcher(s.Store, 0)
	err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2025-0001")
	if err != nil {
		t.Fatalf("Fanout with no channels: got error %v, want nil", err)
	}

	// Verify 0 delivery rows exist.
	var count int
	row := s.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_deliveries WHERE rule_id=$1`,
		rule.ID)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count deliveries: %v", err)
	}
	if count != 0 {
		t.Errorf("delivery rows = %d, want 0 (no channels bound)", count)
	}
}

func TestFanout_SingleChannel_CreatesDeliveryRow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "FanoutSingleOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FanoutSingleRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "FanoutSingleChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	d := notify.NewDispatcher(s.Store, 0)
	err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2025-0002")
	if err != nil {
		t.Fatalf("Fanout: %v", err)
	}

	count := countPendingDeliveries(t, s, ctx, rule.ID, chanID)
	if count != 1 {
		t.Errorf("pending delivery rows = %d, want 1", count)
	}

	// Verify the payload contains the cve_id.
	var raw []byte
	row := s.DB().QueryRowContext(ctx,
		`SELECT payload FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		rule.ID, chanID)
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("scan payload: %v", err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("payload items = %d, want 1", len(items))
	}

	var snap map[string]interface{}
	if err := json.Unmarshal(items[0], &snap); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if snap["cve_id"] != "CVE-2025-0002" {
		t.Errorf("snapshot cve_id = %v, want CVE-2025-0002", snap["cve_id"])
	}
}

func TestFanout_Debounce_AppendsToExistingRow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "FanoutDebounceOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FanoutDebounceRule")
	chanID, _ := mustCreateNotificationChannel(t, s, ctx, org.ID, "FanoutDebounceChan")

	if err := s.BindChannelToRule(ctx, rule.ID, chanID, org.ID); err != nil {
		t.Fatalf("BindChannelToRule: %v", err)
	}

	// Use a non-zero debounce so the row stays pending after both calls.
	d := notify.NewDispatcher(s.Store, 5)

	// First Fanout: creates a new pending row.
	if err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2025-0010"); err != nil {
		t.Fatalf("Fanout (first): %v", err)
	}

	count := countPendingDeliveries(t, s, ctx, rule.ID, chanID)
	if count != 1 {
		t.Fatalf("after first Fanout: pending rows = %d, want 1", count)
	}

	// Second Fanout for the same rule+channel: must debounce (append to existing row).
	if err := d.Fanout(ctx, org.ID, rule.ID, "CVE-2025-0011"); err != nil {
		t.Fatalf("Fanout (second): %v", err)
	}

	// Still only ONE delivery row.
	count = countPendingDeliveries(t, s, ctx, rule.ID, chanID)
	if count != 1 {
		t.Errorf("after second Fanout: pending rows = %d, want 1 (debounce)", count)
	}

	// Payload must contain two snapshots.
	var raw []byte
	row := s.DB().QueryRowContext(ctx,
		`SELECT payload FROM notification_deliveries WHERE rule_id=$1 AND channel_id=$2 AND status='pending'`,
		rule.ID, chanID)
	if err := row.Scan(&raw); err != nil {
		t.Fatalf("scan payload: %v", err)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if len(items) != 2 {
		t.Errorf("payload items = %d, want 2 (one per Fanout call)", len(items))
	}

	// send_after is in the future (5s debounce) — verify the row is NOT yet claimable.
	claimed, err := s.ClaimPendingDeliveries(ctx, 10)
	if err != nil {
		t.Fatalf("ClaimPendingDeliveries: %v", err)
	}
	// Filter to this rule's delivery.
	claimedForRule := 0
	for _, c := range claimed {
		if c.RuleID.UUID == rule.ID {
			claimedForRule++
		}
	}
	// With debounceSeconds=5, send_after = now+5s, so the row must not be claimable yet.
	if claimedForRule != 0 {
		t.Errorf("debounced row should not be claimable immediately, claimed %d", claimedForRule)
	}
}
