// ABOUTME: Test helper that repeats a delivery claim until the due deliveries have been attempted.
// ABOUTME: Keeps delivery tests independent of the order of database clock readings.
package testutil

import (
	"context"
	"testing"
	"time"
)

const (
	// deliveryClaimDeadline bounds the wait for a delivery to become claimable.
	deliveryClaimDeadline = 10 * time.Second
	// deliveryClaimRetryInterval is the pause between claims while a delivery is not yet due.
	deliveryClaimRetryInterval = 10 * time.Millisecond

	// unattemptedDueDeliveriesSQL counts deliveries written to be sent now that no
	// claim has reached. The allowance matches deliveryClaimDeadline; it excludes
	// deliveries a test debounced into the future.
	unattemptedDueDeliveriesSQL = `
SELECT COUNT(*)
FROM notification_deliveries
WHERE status = 'pending'
  AND last_attempted_at IS NULL
  AND send_after <= now() + interval '10 seconds'`
)

// ClaimUntilDeliveriesAttempted calls claim until no delivery written to be sent
// now remains unattempted. send_after and the claim's now() are read in separate
// transactions from a wall clock that can step backward between them, so a single
// claim can find a delivery not yet due.
func (tdb *TestDB) ClaimUntilDeliveriesAttempted(t *testing.T, ctx context.Context, claim func()) {
	t.Helper()
	deadline := time.Now().Add(deliveryClaimDeadline)
	for {
		claim()
		var unattempted int
		if err := tdb.DB().QueryRowContext(ctx, unattemptedDueDeliveriesSQL).Scan(&unattempted); err != nil {
			t.Fatalf("count unattempted deliveries: %v", err)
		}
		if unattempted == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d deliveries still unattempted after %v", unattempted, deliveryClaimDeadline)
		}
		time.Sleep(deliveryClaimRetryInterval)
	}
}
