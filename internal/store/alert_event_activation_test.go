// ABOUTME: Tests RecordActivationAlertEvents, which writes an activation-scan page of matches in one transaction.
// ABOUTME: Compares its rows with the per-event insert-then-reopen path, and checks the feed lock and the CVE existence guard.
package store_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// mustInsertCVERows adds bare cves rows. The activation writer only checks that a CVE
// still exists, so no other column matters here.
func mustInsertCVERows(t *testing.T, s *testutil.TestDB, cveIDs ...string) {
	t.Helper()
	if _, err := s.DB().ExecContext(context.Background(),
		`INSERT INTO cves (cve_id) SELECT unnest($1::text[]) ON CONFLICT (cve_id) DO NOTHING`,
		pq.Array(cveIDs)); err != nil {
		t.Fatalf("insert cves rows: %v", err)
	}
}

// activationEventRow is the part of an alert event that the activation writers decide.
// Moved reports whether the event's feed position changed during the write under test.
type activationEventRow struct {
	CVEID            string
	MaterialHash     string
	LastMatchState   bool
	SuppressDelivery bool
	TimesFired       int32
	Moved            bool
}

// readActivationEvents returns ruleID's events sorted by CVE and hash, comparing each
// feed position with the one in before.
func readActivationEvents(t *testing.T, s *testutil.TestDB, ruleID uuid.UUID, before map[string]int64) []activationEventRow {
	t.Helper()
	rows, err := s.DB().QueryContext(context.Background(), `
		SELECT cve_id, material_hash, last_match_state, suppress_delivery, times_fired, feed_seq
		FROM alert_events WHERE rule_id = $1 ORDER BY cve_id, material_hash`, ruleID)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var out []activationEventRow
	for rows.Next() {
		var r activationEventRow
		var seq int64
		if err := rows.Scan(&r.CVEID, &r.MaterialHash, &r.LastMatchState, &r.SuppressDelivery, &r.TimesFired, &seq); err != nil {
			t.Fatalf("scan event: %v", err)
		}
		prev, ok := before[r.CVEID+"|"+r.MaterialHash]
		r.Moved = !ok || prev != seq
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate events: %v", err)
	}
	return out
}

// feedPositions returns ruleID's feed positions keyed by "cve|hash".
func feedPositions(t *testing.T, s *testutil.TestDB, ruleID uuid.UUID) map[string]int64 {
	t.Helper()
	rows, err := s.DB().QueryContext(context.Background(),
		`SELECT cve_id, material_hash, feed_seq FROM alert_events WHERE rule_id = $1`, ruleID)
	if err != nil {
		t.Fatalf("read feed positions: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	out := map[string]int64{}
	for rows.Next() {
		var cve, hash string
		var seq int64
		if err := rows.Scan(&cve, &hash, &seq); err != nil {
			t.Fatalf("scan feed position: %v", err)
		}
		out[cve+"|"+hash] = seq
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate feed positions: %v", err)
	}
	return out
}

// TestRecordActivationAlertEvents_MatchesPerEventPath gives two rules the same history
// and the same page of matches. One rule's page is written event by event, as activation
// did before pages were written together: skip a CVE that no longer exists, insert, and
// reopen when the insert found the event. The other's page is written by
// RecordActivationAlertEvents. The resulting events must be the same.
func TestRecordActivationAlertEvents_MatchesPerEventPath(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ActivationPageOrg")

	const (
		newCVE      = "CVE-2024-85001" // no event yet
		openCVE     = "CVE-2024-85002" // open event at the matched hash, delivered
		resolvedCVE = "CVE-2024-85003" // resolved event at the matched hash
		rehashedCVE = "CVE-2024-85004" // resolved event at an earlier hash only
		missingCVE  = "CVE-2024-85005" // renamed away: no cves row
		repeatedCVE = "CVE-2024-85006" // appears twice in the page
	)
	mustInsertCVERows(t, s, newCVE, openCVE, resolvedCVE, rehashedCVE, repeatedCVE)

	page := []store.AlertEventMatch{
		{CVEID: newCVE, MaterialHash: "h"},
		{CVEID: openCVE, MaterialHash: "h"},
		{CVEID: resolvedCVE, MaterialHash: "h"},
		{CVEID: rehashedCVE, MaterialHash: "h2"},
		{CVEID: missingCVE, MaterialHash: "h"},
		{CVEID: repeatedCVE, MaterialHash: "h"},
		{CVEID: repeatedCVE, MaterialHash: "h"},
	}

	setUp := func(name string) uuid.UUID {
		rule := mustCreateAlertRule(t, s, ctx, org.ID, name)
		for _, e := range []struct{ cve, hash string }{{openCVE, "h"}, {resolvedCVE, "h"}, {rehashedCVE, "h1"}} {
			if _, err := s.InsertAlertEvent(ctx, org.ID, rule.ID, e.cve, e.hash, false); err != nil {
				t.Fatalf("setup InsertAlertEvent %s: %v", e.cve, err)
			}
		}
		for _, cve := range []string{resolvedCVE, rehashedCVE} {
			if _, err := s.ResolveAlertEvent(ctx, rule.ID, org.ID, cve); err != nil {
				t.Fatalf("setup ResolveAlertEvent %s: %v", cve, err)
			}
		}
		return rule.ID
	}

	perEventRule := setUp("ActivationPagePerEvent")
	perEventBefore := feedPositions(t, s, perEventRule)
	for _, m := range page {
		var exists bool
		if err := s.DB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM cves WHERE cve_id = $1)`, m.CVEID).Scan(&exists); err != nil {
			t.Fatalf("check CVE %s: %v", m.CVEID, err)
		}
		if !exists {
			continue
		}
		id, err := s.InsertAlertEvent(ctx, org.ID, perEventRule, m.CVEID, m.MaterialHash, true)
		if err != nil {
			t.Fatalf("InsertAlertEvent %s: %v", m.CVEID, err)
		}
		if id == uuid.Nil {
			if _, err := s.ReopenAlertEvent(ctx, org.ID, perEventRule, m.CVEID, m.MaterialHash, true); err != nil {
				t.Fatalf("ReopenAlertEvent %s: %v", m.CVEID, err)
			}
		}
	}
	want := readActivationEvents(t, s, perEventRule, perEventBefore)

	pageRule := setUp("ActivationPageBatched")
	pageBefore := feedPositions(t, s, pageRule)
	written, err := s.RecordActivationAlertEvents(ctx, org.ID, pageRule, page)
	if err != nil {
		t.Fatalf("RecordActivationAlertEvents: %v", err)
	}
	got := readActivationEvents(t, s, pageRule, pageBefore)

	if !slices.Equal(got, want) {
		t.Fatalf("events written as a page differ from the per-event path\n got: %+v\nwant: %+v", got, want)
	}
	// new, resolved (reopened), rehashed (new row at h2), repeated (once).
	if written != 4 {
		t.Errorf("written = %d, want 4 (three inserts and one reopen)", written)
	}

	// Spot-check the expectations the comparison relies on, so a shared mistake in
	// both paths cannot pass unnoticed.
	byKey := map[string]activationEventRow{}
	for _, r := range got {
		byKey[r.CVEID+"|"+r.MaterialHash] = r
	}
	if _, ok := byKey[missingCVE+"|h"]; ok {
		t.Error("an event was recorded for a CVE that no longer exists")
	}
	if r := byKey[newCVE+"|h"]; !r.LastMatchState || !r.SuppressDelivery || r.TimesFired != 1 || !r.Moved {
		t.Errorf("new event = %+v, want open, suppressed, fired once, at a new position", r)
	}
	if r := byKey[openCVE+"|h"]; !r.LastMatchState || r.SuppressDelivery || r.TimesFired != 1 || r.Moved {
		t.Errorf("already-open event = %+v, want it unchanged", r)
	}
	if r := byKey[resolvedCVE+"|h"]; !r.LastMatchState || !r.SuppressDelivery || r.TimesFired != 2 || !r.Moved {
		t.Errorf("reopened event = %+v, want open, suppressed, fired twice, at a new position", r)
	}
	if r := byKey[rehashedCVE+"|h1"]; r.LastMatchState || r.Moved {
		t.Errorf("event at the earlier hash = %+v, want it left resolved", r)
	}
	if r := byKey[repeatedCVE+"|h"]; !r.LastMatchState || r.TimesFired != 1 {
		t.Errorf("repeated match = %+v, want one open event fired once", r)
	}

	// Writing the same page again changes nothing.
	again, err := s.RecordActivationAlertEvents(ctx, org.ID, pageRule, page)
	if err != nil {
		t.Fatalf("RecordActivationAlertEvents (again): %v", err)
	}
	if again != 0 {
		t.Errorf("second write of the same page wrote %d events, want 0", again)
	}

	if n, err := s.RecordActivationAlertEvents(ctx, org.ID, pageRule, nil); err != nil || n != 0 {
		t.Errorf("empty page: written %d, err %v; want 0, nil", n, err)
	}
}

// TestRecordActivationAlertEvents_FullPage writes a page of 1,000 matches, the size of
// an activation page, and checks each gets its own feed position.
func TestRecordActivationAlertEvents_FullPage(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ActivationFullPageOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ActivationFullPageRule")

	page := make([]store.AlertEventMatch, 1000)
	ids := make([]string, len(page))
	for i := range page {
		ids[i] = fmt.Sprintf("CVE-2024-9%05d", i)
		page[i] = store.AlertEventMatch{CVEID: ids[i], MaterialHash: "h"}
	}
	mustInsertCVERows(t, s, ids...)

	written, err := s.RecordActivationAlertEvents(ctx, org.ID, rule.ID, page)
	if err != nil {
		t.Fatalf("RecordActivationAlertEvents: %v", err)
	}
	if written != int64(len(page)) {
		t.Fatalf("written = %d, want %d", written, len(page))
	}
	var events, positions int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT count(*), count(DISTINCT feed_seq) FROM alert_events WHERE rule_id = $1 AND suppress_delivery`,
		rule.ID).Scan(&events, &positions); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if events != len(page) || positions != len(page) {
		t.Errorf("suppressed events %d with %d distinct positions, want %d of each", events, positions, len(page))
	}
}

// TestRecordActivationAlertEvents_TakesFeedLock checks that a page write waits for the
// org's feed lock, like every other writer of feed positions.
func TestRecordActivationAlertEvents_TakesFeedLock(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ActivationFeedLockOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ActivationFeedLockRule")
	const cve = "CVE-2024-86001"
	mustInsertCVERows(t, s, cve)

	holder := mustBegin(t, s.DB())
	mustExec(t, holder, lockFeedSQL, org.ID)

	type result struct {
		written int64
		err     error
	}
	done := make(chan result, 1)
	go func() {
		n, err := s.RecordActivationAlertEvents(ctx, org.ID, rule.ID, []store.AlertEventMatch{{CVEID: cve, MaterialHash: "h"}})
		done <- result{n, err}
	}()
	waitForFeedLockWaiter(t, s.DB(), org.ID)
	select {
	case r := <-done:
		t.Fatalf("RecordActivationAlertEvents returned (%d, %v) while the feed lock was held", r.written, r.err)
	default:
	}

	mustCommit(t, holder)
	if r := <-done; r.err != nil || r.written != 1 {
		t.Fatalf("after the lock was released: written %d, err %v; want 1, nil", r.written, r.err)
	}
}

// TestRecordActivationAlertEvents_AppRole writes and reopens a page through the
// application role, which needs USAGE on the feed sequence and SELECT on cves.
func TestRecordActivationAlertEvents_AppRole(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "ActivationAppRoleOrg")
	rule := mustCreateAlertRule(t, s, ctx, org.ID, "ActivationAppRoleRule")
	const cve = "CVE-2024-86101"
	mustInsertCVERows(t, s, cve)
	page := []store.AlertEventMatch{{CVEID: cve, MaterialHash: "h"}}

	if n, err := s.AppStore.RecordActivationAlertEvents(ctx, org.ID, rule.ID, page); err != nil || n != 1 {
		t.Fatalf("AppStore.RecordActivationAlertEvents (insert): written %d, err %v", n, err)
	}
	if _, err := s.AppStore.ResolveAlertEvent(ctx, rule.ID, org.ID, cve); err != nil {
		t.Fatalf("AppStore.ResolveAlertEvent: %v", err)
	}
	if n, err := s.AppStore.RecordActivationAlertEvents(ctx, org.ID, rule.ID, page); err != nil || n != 1 {
		t.Fatalf("AppStore.RecordActivationAlertEvents (reopen): written %d, err %v", n, err)
	}
}
