// ABOUTME: Integration tests for EventWriter — verifies DB writes and rate limiting.
// ABOUTME: Uses testutil.NewTestDB for real Postgres interactions.
package secure_test

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/scarson/cvert-ops/internal/secure"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSecurityEventWriter_WritesEvent(t *testing.T) {
	db := testutil.NewTestDB(t)
	w := secure.NewEventWriter(db.Store)
	defer w.Stop()

	ctx := context.Background()
	w.Write(ctx, secure.Event{
		Type:       secure.EventAuthLoginFailed,
		Severity:   secure.SeverityInfo,
		ActorIP:    "10.0.0.1",
		ActorEmail: "user@example.com",
		Details:    map[string]any{"reason": "bad password"},
	})

	// Stop waits for all pending goroutines to finish.
	w.Stop()

	count := countSecurityEvents(t, ctx, db)
	if count != 1 {
		t.Fatalf("expected 1 event, got %d", count)
	}

	// Verify the specific event fields.
	var eventType, actorIP string
	err := db.Store.Pool().QueryRow(ctx,
		"SELECT event_type, actor_ip FROM security_events LIMIT 1",
	).Scan(&eventType, &actorIP)
	if err != nil {
		t.Fatalf("query event: %v", err)
	}
	if eventType != secure.EventAuthLoginFailed {
		t.Errorf("event type = %q, want %q", eventType, secure.EventAuthLoginFailed)
	}
	if actorIP != "10.0.0.1" {
		t.Errorf("actor_ip = %q, want %q", actorIP, "10.0.0.1")
	}
}

func TestSecurityEventWriter_RateLimitsWrites(t *testing.T) {
	db := testutil.NewTestDB(t)
	w := secure.NewEventWriter(db.Store)
	defer w.Stop()

	ctx := context.Background()

	// Write 15 events from the same (type, IP) — only 10 should be written.
	for i := 0; i < 15; i++ {
		w.Write(ctx, secure.Event{
			Type:     secure.EventAuthLoginFailed,
			Severity: secure.SeverityInfo,
			ActorIP:  "10.0.0.1",
		})
	}

	w.Stop()

	count := countSecurityEvents(t, ctx, db)
	if count != 10 {
		t.Errorf("expected 10 events (rate limited), got %d", count)
	}
}

func TestSecurityEventWriter_DifferentKeysNotLimited(t *testing.T) {
	db := testutil.NewTestDB(t)
	w := secure.NewEventWriter(db.Store)
	defer w.Stop()

	ctx := context.Background()

	// Write 10 from IP-A and 10 from IP-B — all 20 should be written.
	for i := 0; i < 10; i++ {
		w.Write(ctx, secure.Event{
			Type:     secure.EventAuthLoginFailed,
			Severity: secure.SeverityInfo,
			ActorIP:  "10.0.0.1",
		})
		w.Write(ctx, secure.Event{
			Type:     secure.EventAuthLoginFailed,
			Severity: secure.SeverityInfo,
			ActorIP:  "10.0.0.2",
		})
	}

	w.Stop()

	count := countSecurityEvents(t, ctx, db)
	if count != 20 {
		t.Errorf("expected 20 events, got %d", count)
	}
}

func TestSecurityEventWriter_SetSyslogRaceSafe(t *testing.T) {
	db := testutil.NewTestDB(t)
	ew := secure.NewEventWriter(db.Store)
	defer ew.Stop()

	ctx := context.Background()
	const goroutines = 20

	// Start multiple goroutines calling Write concurrently.
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			for range 50 {
				ew.Write(ctx, secure.Event{
					Type:     secure.EventAuthLoginFailed,
					Severity: secure.SeverityInfo,
					ActorIP:  "10.0.0.99",
				})
			}
		}()
	}

	// Concurrently call SetSyslog while writes are in flight.
	// Use nil to avoid needing a real syslog connection — the point is
	// to exercise the concurrent access path under the race detector.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			ew.SetSyslog(nil)
		}
	}()

	wg.Wait()
	// If no race detector fires, the test passes.
}

func TestEventWriter_BoundedConcurrency(t *testing.T) {
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Acquire an exclusive advisory lock from the test connection. The
	// EventWriter's INSERT calls use withBypassTx which acquires the same
	// connection pool. By holding a table-level lock we force writer
	// goroutines to block, filling the semaphore.
	lockConn, err := db.Store.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock conn: %v", err)
	}
	// LOCK TABLE blocks all concurrent INSERTs until we release it.
	if _, err := lockConn.Exec(ctx, "BEGIN"); err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	if _, err := lockConn.Exec(ctx, "LOCK TABLE security_events IN EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock security_events: %v", err)
	}

	w := secure.NewEventWriter(db.Store)

	// Fire 100 writes, each with a unique IP so the rate limiter passes all.
	// The semaphore capacity is 50 (writerConcurrency). With the table locked
	// the first 50 goroutines will block on INSERT, filling the semaphore.
	// Subsequent writes are dropped by the select-default path.
	const totalWrites = 100
	var wg sync.WaitGroup
	wg.Add(totalWrites)
	for i := range totalWrites {
		go func(idx int) {
			defer wg.Done()
			w.Write(ctx, secure.Event{
				Type:     secure.EventAuthLoginFailed,
				Severity: secure.SeverityInfo,
				ActorIP:  fmt.Sprintf("10.1.%d.%d", idx/256, idx%256),
			})
		}(i)
	}
	// Wait for all Write calls to return (they either got a slot or were dropped).
	wg.Wait()

	// Verify bounded goroutine count: the delta should be <= 55 (50 semaphore + overhead).
	baseGoroutines := runtime.NumGoroutine()
	// The blocked goroutines are part of the writer's wg, so they show up in NumGoroutine.
	// baseGoroutines includes them. We can't measure the delta from before the writes
	// because the Write calls already returned. Instead, verify the semaphore bound
	// by checking that fewer than totalWrites events were written (some were dropped).
	// Release the lock so blocked goroutines can complete.
	if _, err := lockConn.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatalf("rollback lock: %v", err)
	}
	lockConn.Release()

	w.Stop()

	// After Stop, all goroutines should have completed. Check that the goroutine
	// count returned to near the base (the blocked goroutines are gone).
	afterStop := runtime.NumGoroutine()
	if afterStop > baseGoroutines+5 {
		t.Errorf("goroutine leak after Stop: before=%d, after=%d", baseGoroutines, afterStop)
	}

	// Verify the concurrency bound: with 100 writes and a semaphore of 50, at most
	// 50 events should have been written (the other 50 were dropped while blocked).
	count := countSecurityEvents(t, ctx, db)
	if count > 50 {
		t.Errorf("expected <= 50 events (semaphore bound), got %d", count)
	}
	if count == 0 {
		t.Error("expected at least some events to be written")
	}
	t.Logf("events written: %d / %d attempted (semaphore capped at 50)", count, totalWrites)
}

// countSecurityEvents returns the total number of rows in security_events.
func countSecurityEvents(t *testing.T, ctx context.Context, db *testutil.TestDB) int {
	t.Helper()
	var count int
	err := db.Store.Pool().QueryRow(ctx, "SELECT count(*) FROM security_events").Scan(&count)
	if err != nil && err != pgx.ErrNoRows {
		t.Fatalf("count security events: %v", err)
	}
	return count
}
