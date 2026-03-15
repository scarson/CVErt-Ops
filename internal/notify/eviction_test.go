// ABOUTME: Internal unit tests for semaphore eviction and worker health reporting.
// ABOUTME: Uses package notify (not notify_test) to access unexported fields.
package notify

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestEvictStaleSemaphores_EvictsStale(t *testing.T) {
	t.Parallel()

	w := &Worker{
		cfg:          WorkerConfig{MaxConcurrentPerOrg: 1},
		sems:         make(map[uuid.UUID]chan struct{}),
		semsLastUsed: make(map[uuid.UUID]time.Time),
	}

	orgID := uuid.New()
	w.semaphore(orgID)

	if len(w.sems) != 1 {
		t.Fatalf("sems length = %d, want 1", len(w.sems))
	}

	// Backdate last-used to 15 minutes ago (exceeds 10-minute eviction age).
	w.semsLastUsed[orgID] = time.Now().Add(-15 * time.Minute)

	w.evictStaleSemaphores()

	if len(w.sems) != 0 {
		t.Errorf("after eviction: sems length = %d, want 0", len(w.sems))
	}
	if len(w.semsLastUsed) != 0 {
		t.Errorf("after eviction: semsLastUsed length = %d, want 0", len(w.semsLastUsed))
	}
}

func TestEvictStaleSemaphores_PreservesInFlight(t *testing.T) {
	t.Parallel()

	w := &Worker{
		cfg:          WorkerConfig{MaxConcurrentPerOrg: 1},
		sems:         make(map[uuid.UUID]chan struct{}),
		semsLastUsed: make(map[uuid.UUID]time.Time),
	}

	orgID := uuid.New()
	w.semaphore(orgID)

	// Simulate an in-flight delivery by writing to the semaphore channel.
	w.sems[orgID] <- struct{}{}

	// Backdate last-used to 15 minutes ago.
	w.semsLastUsed[orgID] = time.Now().Add(-15 * time.Minute)

	w.evictStaleSemaphores()

	// Semaphore must be preserved because a delivery is in flight.
	if len(w.sems) != 1 {
		t.Errorf("after eviction with in-flight: sems length = %d, want 1", len(w.sems))
	}
}
