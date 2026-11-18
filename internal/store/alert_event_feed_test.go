// ABOUTME: Tests the ascending alert-event feed: positions are drawn under the org's feed lock, so
// ABOUTME: they become visible in position order and a poller sees each change to an event exactly once.
package store_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// lockFeedSQL takes an org's feed lock the way the store does (LockAlertEventFeed).
const lockFeedSQL = `SELECT pg_advisory_xact_lock(1178944836, hashtext($1::uuid::text))`

// insertLockedSQL inserts an event the way a correct writer must: under the feed lock.
const insertLockedSQL = `INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, feed_seq)
	VALUES ($1, $2, $3, 'h', nextval('alert_event_feed_seq'))`

// feedPoller reads the ascending feed as a client does: it keeps the last position
// and resumes from it.
type feedPoller struct {
	t     *testing.T
	s     *testutil.TestDB
	org   uuid.UUID
	limit int
	after *int64
	seen  []string
}

// poll reads one page through the application role (RLS applies) and returns its events.
func (p *feedPoller) poll() []store.AlertEventListRow {
	p.t.Helper()
	rows, err := p.s.AppStore.ListAlertEvents(context.Background(), p.org,
		store.ListAlertEventsParams{Ascending: true, AfterSeq: p.after, Limit: p.limit})
	if err != nil {
		p.t.Fatalf("ListAlertEvents: %v", err)
	}
	for _, r := range rows {
		p.seen = append(p.seen, r.CveID)
		seq := r.FeedSeq
		p.after = &seq
	}
	return rows
}

// drain polls until a page comes back short.
func (p *feedPoller) drain() {
	p.t.Helper()
	for {
		if len(p.poll()) < p.limit {
			return
		}
	}
}

func (p *feedPoller) requireSeen(want ...string) {
	p.t.Helper()
	if len(p.seen) != len(want) {
		p.t.Fatalf("seen %v, want %v", p.seen, want)
	}
	for i := range want {
		if p.seen[i] != want[i] {
			p.t.Fatalf("seen %v, want %v", p.seen, want)
		}
	}
}

func mustBegin(t *testing.T, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

func mustExec(t *testing.T, tx *sql.Tx, query string, args ...any) {
	t.Helper()
	if _, err := tx.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func mustCommit(t *testing.T, tx *sql.Tx) {
	t.Helper()
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// waitForFeedLockWaiter returns once some session in this database is waiting for
// org's feed lock, or fails after 30 seconds.
func waitForFeedLockWaiter(t *testing.T, db *sql.DB, org uuid.UUID) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var waiting bool
		if err := db.QueryRowContext(context.Background(), `SELECT EXISTS (
			SELECT 1 FROM pg_locks
			WHERE locktype = 'advisory' AND NOT granted
			  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
			  AND classid = 1178944836 AND objid = hashtext($1::uuid::text)::oid AND objsubid = 2)`,
			org).Scan(&waiting); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		if waiting {
			return
		}
	}
	t.Fatalf("no session waited for the feed lock of org %s", org)
}

// TestAlertEventFeed_WritersTakeFeedLock checks that InsertAlertEvent,
// ReopenAlertEvent and ResolveAlertEvent wait for the org's feed lock. Without it, a
// position drawn by one transaction could become visible before a smaller one drawn
// by another.
func TestAlertEventFeed_WritersTakeFeedLock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedLockOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedLockRule")
	const cve = "CVE-2024-82001"

	type result struct {
		changed bool
		err     error
	}
	// Each case changes the event, so it must draw a position under the lock.
	for _, tc := range []struct {
		name  string
		write func() (bool, error)
	}{
		{"insert", func() (bool, error) {
			id, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false)
			return id != uuid.Nil, err
		}},
		{"resolve", func() (bool, error) {
			return s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve)
		}},
		{"reopen", func() (bool, error) {
			id, err := s.ReopenAlertEvent(ctx, org.ID, rule.ID, cve, "h", false)
			return id != uuid.Nil, err
		}},
	} {
		holder := mustBegin(t, s.DB())
		mustExec(t, holder, lockFeedSQL, org.ID)

		done := make(chan result, 1)
		go func() {
			changed, err := tc.write()
			done <- result{changed, err}
		}()
		waitForFeedLockWaiter(t, s.DB(), org.ID)
		select {
		case r := <-done:
			t.Fatalf("%s returned (%v, %v) while the feed lock was held", tc.name, r.changed, r.err)
		default:
		}

		mustCommit(t, holder)
		r := <-done
		if r.err != nil || !r.changed {
			t.Fatalf("%s after the lock was released: changed %v, err %v", tc.name, r.changed, r.err)
		}
	}
}

// TestAlertEventFeed_AppRoleCanDrawPositions inserts and reopens through the
// application role, which needs USAGE on the feed sequence.
func TestAlertEventFeed_AppRoleCanDrawPositions(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedAppRoleOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedAppRoleRule")

	if id, err := s.AppStore.InsertAlertEvent(ctx, org.ID, rule.ID, "CVE-2024-82101", "h", false); err != nil || id == uuid.Nil {
		t.Fatalf("AppStore.InsertAlertEvent: id %v, err %v", id, err)
	}
	if _, err := s.AppStore.ResolveAlertEvent(ctx, rule.ID, org.ID, "CVE-2024-82101"); err != nil {
		t.Fatalf("AppStore.ResolveAlertEvent: %v", err)
	}
	if id, err := s.AppStore.ReopenAlertEvent(ctx, org.ID, rule.ID, "CVE-2024-82101", "h", false); err != nil || id == uuid.Nil {
		t.Fatalf("AppStore.ReopenAlertEvent: id %v, err %v", id, err)
	}
}

// TestAlertEventFeed_ConcurrentWritersDoNotDeadlock races an insert, a reopen and a
// resolve of the same event many times. Each takes the feed lock before the row, so
// none can hold the row while waiting for the lock.
func TestAlertEventFeed_ConcurrentWritersDoNotDeadlock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedDeadlockOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedDeadlockRule")
	const cve = "CVE-2024-82201"
	if _, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false); err != nil {
		t.Fatalf("InsertAlertEvent: %v", err)
	}

	for i := range 200 {
		errs := make(chan error, 3)
		go func() {
			_, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false)
			errs <- err
		}()
		go func() {
			_, err := s.ReopenAlertEvent(ctx, org.ID, rule.ID, cve, "h", false)
			errs <- err
		}()
		go func() {
			_, err := s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve)
			errs <- err
		}()
		for range 3 {
			if err := <-errs; err != nil {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
					t.Fatalf("iteration %d: deadlock: %v", i, err)
				}
				t.Fatalf("iteration %d: %v", i, err)
			}
		}
	}
}

// TestListAlertEvents_AscendingConcurrentWriters is the feed's acceptance test: a
// writer that starts later cannot make its event visible before an earlier writer's,
// so a poller that stores its position sees every event exactly once, in order.
func TestListAlertEvents_AscendingConcurrentWriters(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedRule")

	early := mustBegin(t, s.DB())
	mustExec(t, early, lockFeedSQL, org.ID)
	mustExec(t, early, insertLockedSQL, org.ID, rule.ID, "CVE-2024-80001")

	late := make(chan error, 1)
	go func() {
		_, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, "CVE-2024-80002", "h", false)
		late <- err
	}()
	waitForFeedLockWaiter(t, s.DB(), org.ID)

	p := &feedPoller{t: t, s: s, org: org.ID, limit: 10}
	if rows := p.poll(); len(rows) != 0 {
		t.Fatalf("poll while the first writer is open returned %v, want nothing", p.seen)
	}
	mustCommit(t, early)
	if err := <-late; err != nil {
		t.Fatalf("later InsertAlertEvent: %v", err)
	}
	p.poll()
	p.requireSeen("CVE-2024-80001", "CVE-2024-80002")
	if rows := p.poll(); len(rows) != 0 {
		t.Fatalf("poll after catching up returned more: seen %v", p.seen)
	}
}

// TestListAlertEvents_AscendingPagesInFeedOrder pages with limit 2 through events
// interleaved with another org's, including three written by one transaction.
func TestListAlertEvents_AscendingPagesInFeedOrder(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedPagesOrg")
	other := s.MustCreateOrg(t, ctx, "FeedPagesOther")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedPagesRule")
	otherRule := mustCreateAlertRule(t, s, ctx, other.ID, "FeedPagesOtherRule")

	for _, cve := range []string{"CVE-2024-81001", "CVE-2024-81002"} {
		if _, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false); err != nil {
			t.Fatalf("InsertAlertEvent: %v", err)
		}
		if _, err := s.InsertAlertEvent(ctx, other.ID, otherRule.ID, cve, "h", false); err != nil {
			t.Fatalf("InsertAlertEvent(other): %v", err)
		}
	}
	// One transaction, three events: a page boundary falls inside it.
	tx := mustBegin(t, s.DB())
	mustExec(t, tx, lockFeedSQL, org.ID)
	for _, cve := range []string{"CVE-2024-81003", "CVE-2024-81004", "CVE-2024-81005"} {
		mustExec(t, tx, insertLockedSQL, org.ID, rule.ID, cve)
	}
	mustCommit(t, tx)

	p := &feedPoller{t: t, s: s, org: org.ID, limit: 2}
	p.drain()
	p.requireSeen("CVE-2024-81001", "CVE-2024-81002", "CVE-2024-81003", "CVE-2024-81004", "CVE-2024-81005")

	desc, err := s.AppStore.ListAlertEvents(ctx, org.ID, store.ListAlertEventsParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListAlertEvents(desc): %v", err)
	}
	if len(desc) != 5 {
		t.Errorf("descending list has %d events, want 5", len(desc))
	}
}

// TestListAlertEvents_AscendingChangesReenterFeed returns an event again each time it
// changes: a resolve shows it closed, a reopen shows it firing again.
func TestListAlertEvents_AscendingChangesReenterFeed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedChangesOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedChangesRule")
	const cve = "CVE-2024-83001"

	p := &feedPoller{t: t, s: s, org: org.ID, limit: 10}
	if rows := p.poll(); len(rows) != 0 || p.after != nil {
		t.Fatalf("first poll of an empty feed: %d events, position %v; want none", len(rows), p.after)
	}
	if _, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false); err != nil {
		t.Fatalf("InsertAlertEvent: %v", err)
	}
	if rows := p.poll(); len(rows) != 1 || !rows[0].LastMatchState {
		t.Fatalf("after insert: %+v, want the open event", rows)
	}
	if _, err := s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve); err != nil {
		t.Fatalf("ResolveAlertEvent: %v", err)
	}
	if rows := p.poll(); len(rows) != 1 || rows[0].LastMatchState {
		t.Fatalf("after resolve: %+v, want the event, closed", rows)
	}
	if _, err := s.ReopenAlertEvent(ctx, org.ID, rule.ID, cve, "h", false); err != nil {
		t.Fatalf("ReopenAlertEvent: %v", err)
	}
	rows := p.poll()
	if len(rows) != 1 || rows[0].TimesFired != 2 || !rows[0].LastMatchState {
		t.Fatalf("after reopen: %+v, want the event open with times_fired 2", rows)
	}
	if rows := p.poll(); len(rows) != 0 {
		t.Fatalf("poll after catching up returned more: seen %v", p.seen)
	}
	p.requireSeen(cve, cve, cve)

	// A resolve that changes nothing does not move the event.
	if _, err := s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve); err != nil {
		t.Fatalf("ResolveAlertEvent: %v", err)
	}
	if _, err := s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve); err != nil {
		t.Fatalf("ResolveAlertEvent (again): %v", err)
	}
	p.poll()
	p.requireSeen(cve, cve, cve, cve)
}

// TestListAlertEvents_AscendingResumesAfterDeletedPosition resumes from a position
// whose event retention has deleted, and reads history (negative positions) first.
func TestListAlertEvents_AscendingResumesAfterDeletedPosition(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "FeedResumeOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "FeedResumeRule")

	// Events backfilled by migration 000062 hold negative positions.
	for i, cve := range []string{"CVE-2024-84001", "CVE-2024-84002"} {
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO alert_events (org_id, rule_id, cve_id, material_hash, feed_seq)
			VALUES ($1, $2, $3, 'h', $4)`, org.ID, rule.ID, cve, int64(i-2)); err != nil {
			t.Fatalf("insert history: %v", err)
		}
	}
	for _, cve := range []string{"CVE-2024-84003", "CVE-2024-84004"} {
		if _, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, cve, "h", false); err != nil {
			t.Fatalf("InsertAlertEvent: %v", err)
		}
	}

	p := &feedPoller{t: t, s: s, org: org.ID, limit: 1}
	p.poll()
	p.poll()
	p.requireSeen("CVE-2024-84001", "CVE-2024-84002")
	if *p.after != -1 {
		t.Fatalf("position after history = %d, want -1", *p.after)
	}
	if _, err := s.DB().ExecContext(ctx, `DELETE FROM alert_events WHERE org_id = $1 AND cve_id = 'CVE-2024-84002'`, org.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	p.limit = 10
	p.poll()
	p.requireSeen("CVE-2024-84001", "CVE-2024-84002", "CVE-2024-84003", "CVE-2024-84004")
}
