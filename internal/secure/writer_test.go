// ABOUTME: Integration tests for EventWriter — verifies DB writes and rate limiting.
// ABOUTME: Uses testutil.NewTestDB for real Postgres interactions.
package secure_test

import (
	"context"
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
