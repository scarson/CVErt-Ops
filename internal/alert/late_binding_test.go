// ABOUTME: Tests that an alert follows a CVE that is renamed by late-binding.
// ABOUTME: The promoting merge runs as the application role, so row-level security applies to it.
package alert_test

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func kevPatch(cveID, sourceID string) feed.CanonicalPatch {
	inKEV := true
	return feed.CanonicalPatch{CVEID: cveID, SourceID: sourceID, InCISAKEV: &inKEV}
}

func eventFor(t *testing.T, ctx context.Context, f *cveListFixture, cveID string) (uuid.UUID, bool) {
	t.Helper()
	var id uuid.UUID
	var open bool
	if err := f.db.QueryRowContext(ctx,
		`SELECT id, last_match_state FROM alert_events WHERE rule_id = $1 AND cve_id = $2`, f.rule.ID, cveID).Scan(&id, &open); err != nil {
		t.Fatalf("read event for %s: %v", cveID, err)
	}
	return id, open
}

func TestLateBinding_MovesOpenAlertToNewCVE(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const native, cve = "GHSA-late-move", "CVE-2026-40001"
	if err := merge.Ingest(ctx, tdb.Store, kevPatch(native, native), "osv"); err != nil {
		t.Fatalf("merge.Ingest: %v", err)
	}

	orgs := []*cveListFixture{newCVEListFixture(t, ctx, tdb, kevCondition), newCVEListFixture(t, ctx, tdb, kevCondition)}
	ids := make([]uuid.UUID, len(orgs))
	for i, f := range orgs {
		f.push(t, ctx, native, cve)
		f.evaluateBatch(t, ctx)
		ids[i], _ = eventFor(t, ctx, f, native)
	}

	if err := merge.Ingest(ctx, tdb.AppStore, kevPatch(cve, native), "osv"); err != nil {
		t.Fatalf("merge.Ingest (promotion): %v", err)
	}

	for i, f := range orgs {
		id, open := eventFor(t, ctx, f, cve)
		if id != ids[i] || !open {
			t.Errorf("org %d: event %s open=%v, want %s open", i, id, open, ids[i])
		}
		if n := countAlertEvents(t, f.db, f.rule.ID, native); n != 0 {
			t.Errorf("org %d: %d events remain under the old ID", i, n)
		}
		f.evaluateBatch(t, ctx)
		if n := f.fanouts(cve); n != 0 {
			t.Errorf("org %d: %d notifications for the moved event, want 0", i, n)
		}
	}
}

func TestLateBinding_EventCollidingAtTargetIsClosed(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const native, cve = "GHSA-late-collide", "CVE-2026-40002"
	for _, p := range []feed.CanonicalPatch{kevPatch(native, native), kevPatch(cve, "KEV-"+cve)} {
		if err := merge.Ingest(ctx, tdb.Store, p, "osv"); err != nil {
			t.Fatalf("merge.Ingest: %v", err)
		}
	}
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.push(t, ctx, native, cve)
	f.evaluateBatch(t, ctx)
	targetID, _ := eventFor(t, ctx, f, cve)

	if err := merge.Ingest(ctx, tdb.AppStore, kevPatch(cve, native), "osv"); err != nil {
		t.Fatalf("merge.Ingest (promotion): %v", err)
	}

	if _, open := eventFor(t, ctx, f, native); open {
		t.Error("the colliding event under the old ID is still open")
	}
	if id, _ := eventFor(t, ctx, f, cve); id != targetID {
		t.Errorf("target event = %s, want %s unchanged", id, targetID)
	}
}

// TestLateBinding_UnchangedTargetResolvesMovedAlert moves an alert onto a CVE whose hash
// does not change and which is outside the batch window. The rule's watchlist names only
// the old ID, so the moved alert no longer matches and must resolve.
func TestLateBinding_UnchangedTargetResolvesMovedAlert(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const native, cve = "GHSA-late-unchanged", "CVE-2026-40003"
	for _, p := range []feed.CanonicalPatch{kevPatch(native, native), kevPatch(cve, "KEV-"+cve)} {
		if err := merge.Ingest(ctx, tdb.Store, p, "osv"); err != nil {
			t.Fatalf("merge.Ingest: %v", err)
		}
	}
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.push(t, ctx, native)
	f.evaluateBatch(t, ctx)
	ageCorpus(t, ctx, f.db)
	f.evaluateBatch(t, ctx)

	if err := merge.Ingest(ctx, tdb.AppStore, kevPatch(cve, native), "osv"); err != nil {
		t.Fatalf("merge.Ingest (promotion): %v", err)
	}
	f.evaluateBatch(t, ctx)

	if _, open := eventFor(t, ctx, f, cve); open {
		t.Error("the moved alert is still open although the rule no longer matches the CVE")
	}
}

// renamingStore performs a late-binding promotion at the point evaluateRule has finished
// its candidate query and has not yet started inserting events.
type renamingStore struct {
	store.AlertRuleStore
	rename func()
	once   sync.Once
}

func (s *renamingStore) GetUnresolvedAlertEventCVEs(ctx context.Context, ruleID, orgID uuid.UUID) ([]string, error) {
	s.once.Do(s.rename)
	return s.AlertRuleStore.GetUnresolvedAlertEventCVEs(ctx, ruleID, orgID)
}

func TestEvaluate_SkipsCVERenamedAfterCandidateRead(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const native, cve = "GHSA-late-racing", "CVE-2026-40004"
	if err := merge.Ingest(ctx, tdb.Store, kevPatch(native, native), "osv"); err != nil {
		t.Fatalf("merge.Ingest: %v", err)
	}
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.push(t, ctx, native, cve)

	rules := &renamingStore{AlertRuleStore: tdb.AppStore, rename: func() {
		if err := merge.Ingest(ctx, tdb.Store, kevPatch(cve, native), "osv"); err != nil {
			t.Errorf("merge.Ingest (promotion): %v", err)
		}
	}}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	evaluator := alert.New(tdb.AppStore.DB(), rules, alert.NewRuleCache(), log, 0)
	evaluator.SetDispatcher(f.dispatcher)
	if err := evaluator.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}

	if n := countAlertEvents(t, f.db, f.rule.ID, native); n != 0 {
		t.Errorf("%d events recorded under a renamed CVE", n)
	}
	if n := f.fanouts(native); n != 0 {
		t.Errorf("%d notifications for a renamed CVE", n)
	}
}
