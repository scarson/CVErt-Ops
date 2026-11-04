// ABOUTME: Integration tests for store/admin_delivery.go — site admin retries of failed deliveries.
// ABOUTME: Uses testutil.NewTestDB and the delivery helpers in notification_delivery_test.go.
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestAdminRetryAlertDelivery_NewerBatchPending covers an admin retry of a failed
// alert delivery while a newer batch for the same rule and channel is pending.
func TestAdminRetryAlertDelivery_NewerBatchPending(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "AdminRetryBatch")
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2025-5001"}`), 0)
	ids := claimAndMarkProcessing(t, s, ctx)
	failure := store.DeliveryFailure{Detail: "permanent failure", ForOrg: "permanent failure"}
	if err := s.ExhaustDelivery(ctx, ids[0], failure); err != nil {
		t.Fatalf("ExhaustDelivery: %v", err)
	}
	mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"CVE-2025-5002"}`), 0)

	n, err := s.AdminRetryDelivery(ctx, ids[0])
	if err != nil {
		t.Fatalf("AdminRetryDelivery: %v", err)
	}
	if n != 1 {
		t.Errorf("AdminRetryDelivery rows = %d, want 1", n)
	}

	if n := countAlertDeliveries(t, s, ctx, ruleID, chanID, "failed"); n != 0 {
		t.Errorf("failed deliveries = %d, want 0", n)
	}
	assertPendingAlertCVEs(t, s, ctx, ruleID, chanID, "CVE-2025-5001", "CVE-2025-5002")
}

// TestAdminBulkRetryFailed_TwoAlertBatchesFailed covers a bulk retry of two failed
// alert deliveries for the same rule and channel, which one statement returns to
// pending together.
func TestAdminBulkRetryFailed_TwoAlertBatchesFailed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgID, ruleID, chanID := setupDeliveryFixture(t, s, ctx, "AdminBulkBatch")
	failure := store.DeliveryFailure{Detail: "permanent failure", ForOrg: "permanent failure"}
	for _, cveID := range []string{"CVE-2025-6001", "CVE-2025-6002"} {
		mustUpsertDelivery(t, s, ctx, orgID, ruleID, chanID, []byte(`{"cve_id":"`+cveID+`"}`), 0)
		ids := claimAndMarkProcessing(t, s, ctx)
		if err := s.ExhaustDelivery(ctx, ids[0], failure); err != nil {
			t.Fatalf("ExhaustDelivery: %v", err)
		}
	}

	n, err := s.AdminBulkRetryFailed(ctx, 10)
	if err != nil {
		t.Fatalf("AdminBulkRetryFailed: %v", err)
	}
	if n != 2 {
		t.Errorf("AdminBulkRetryFailed rows = %d, want 2", n)
	}

	if n := countAlertDeliveries(t, s, ctx, ruleID, chanID, "failed"); n != 0 {
		t.Errorf("failed deliveries = %d, want 0", n)
	}
	assertPendingAlertCVEs(t, s, ctx, ruleID, chanID, "CVE-2025-6001", "CVE-2025-6002")
}
