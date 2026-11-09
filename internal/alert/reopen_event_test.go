// ABOUTME: Integration tests that a resolved alert event reopens and fires when its CVE matches the rule again.
// ABOUTME: Moves CVEs out of and back into a rule's match set through the merge pipeline and the EPSS adapter.
package alert_test

import (
	"context"
	"database/sql"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// fanoutsFor counts notifications for one rule and CVE. Each test shares a database with
// earlier rules that also match its CVE, so the count is scoped to the rule under test.
func (m *mockDispatcher) fanoutsFor(ruleID uuid.UUID, cveID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.ruleID == ruleID && c.cveID == cveID {
			n++
		}
	}
	return n
}

func assertEventReopened(t *testing.T, db *sql.DB, disp *mockDispatcher, ruleID uuid.UUID, cveID string, wantFanouts int) {
	t.Helper()
	if n := countAlertEvents(t, db, ruleID, cveID); n != 1 {
		t.Errorf("alert events = %d, want 1 (the CVE returned to a material_hash the rule already fired on)", n)
	}
	if !getMatchState(t, db, ruleID, cveID) {
		t.Error("last_match_state = false, want true (the CVE matches the rule again)")
	}
	if n := disp.fanoutsFor(ruleID, cveID); n != wantFanouts {
		t.Errorf("notifications = %d, want %d", n, wantFanouts)
	}
}

// TestResolvedEventReopensWhenCVEMatchesAgain covers each evaluation path that can see a
// CVE return: a reversed rejection on the realtime and batch paths, and an EPSS score that
// drops below a rule's threshold and comes back, which leaves material_hash unchanged.
func TestResolvedEventReopensWhenCVEMatchesAgain(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	t.Run("Realtime", func(t *testing.T) {
		cveID := "CVE-2099-5000"
		ingestCritical(t, ctx, tdb, cveID)
		rule := mustRule(t, ctx, tdb.Store, orgID, "and", criticalSeverityCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		evaluate := func(stage string) {
			t.Helper()
			if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
				t.Fatalf("EvaluateRealtime %s: %v", stage, err)
			}
		}

		evaluate("after first match")
		assertEventOpen(t, tdb.DB(), rule.ID, cveID)

		ingestRetraction(t, ctx, tdb, cveID, "Rejected")
		evaluate("after rejection")
		assertEventResolved(t, tdb.DB(), rule.ID, cveID)
		if n := disp.fanoutsFor(rule.ID, cveID); n != 1 {
			t.Fatalf("notifications before the CVE returned = %d, want 1", n)
		}

		ingestCritical(t, ctx, tdb, cveID)
		evaluate("after rejection reversed")
		assertEventReopened(t, tdb.DB(), disp, rule.ID, cveID, 2)

		evaluate("re-scan of the reopened event")
		assertEventReopened(t, tdb.DB(), disp, rule.ID, cveID, 2)
	})

	t.Run("Batch", func(t *testing.T) {
		cveID := "CVE-2099-5001"
		ingestCritical(t, ctx, tdb, cveID)
		rule := mustRule(t, ctx, tdb.Store, orgID, "and", criticalSeverityCondition, nil)
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)

		evaluate := func(stage string) {
			t.Helper()
			if err := ev.EvaluateBatch(ctx); err != nil {
				t.Fatalf("EvaluateBatch %s: %v", stage, err)
			}
		}

		evaluate("after first match")
		assertEventOpen(t, tdb.DB(), rule.ID, cveID)

		ageCorpus(t, ctx, tdb.DB())
		ingestRetraction(t, ctx, tdb, cveID, "Rejected")
		evaluate("after rejection")
		assertEventResolved(t, tdb.DB(), rule.ID, cveID)

		ageCorpus(t, ctx, tdb.DB())
		ingestCritical(t, ctx, tdb, cveID)
		evaluate("after rejection reversed")
		assertEventReopened(t, tdb.DB(), disp, rule.ID, cveID, 2)

		evaluate("re-scan of the reopened event")
		assertEventReopened(t, tdb.DB(), disp, rule.ID, cveID, 2)
	})

	t.Run("EPSSScoreReturns", func(t *testing.T) {
		cveID := "CVE-2099-5002"
		ruleID := openEPSSOnlyEvent(t, ctx, tdb, ev, orgID, cveID)

		evaluate := func(stage string) {
			t.Helper()
			if err := ev.EvaluateEPSS(ctx); err != nil {
				t.Fatalf("EvaluateEPSS %s: %v", stage, err)
			}
		}

		ageCorpus(t, ctx, tdb.DB())
		applyEPSSScore(t, ctx, tdb, cveID, 0.1)
		evaluate("after score dropped")
		assertEventResolved(t, tdb.DB(), ruleID, cveID)

		ageCorpus(t, ctx, tdb.DB())
		applyEPSSScore(t, ctx, tdb, cveID, 0.95)
		evaluate("after score returned")
		assertEventReopened(t, tdb.DB(), disp, ruleID, cveID, 2)

		evaluate("re-scan of the reopened event")
		assertEventReopened(t, tdb.DB(), disp, ruleID, cveID, 2)
	})
}

// resolveThenReturn opens an event, resolves it with a rejection, and reverses the
// rejection without evaluating again. It returns the rule's ID.
func resolveThenReturn(t *testing.T, ctx context.Context, tdb *testutil.TestDB, ev *alert.Evaluator, orgID uuid.UUID, cveID string) uuid.UUID {
	t.Helper()
	ingestCritical(t, ctx, tdb, cveID)
	rule := mustRule(t, ctx, tdb.Store, orgID, "and", criticalSeverityCondition, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime after first match: %v", err)
	}
	ingestRetraction(t, ctx, tdb, cveID, "Rejected")
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime after rejection: %v", err)
	}
	assertEventResolved(t, tdb.DB(), rule.ID, cveID)
	ingestCritical(t, ctx, tdb, cveID)
	return rule.ID
}

// TestReopenFiresOnceAcrossConcurrentEvaluators runs evaluators that all see the CVE
// matching again while its event is still resolved. Only one of them may notify.
func TestReopenFiresOnceAcrossConcurrentEvaluators(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	cveID := "CVE-2099-5100"
	ruleID := resolveThenReturn(t, ctx, tdb, ev, orgID, cveID)

	const evaluators = 8
	start := make(chan struct{})
	errs := make([]error, evaluators)
	var wg sync.WaitGroup
	for i := range evaluators {
		wg.Go(func() {
			<-start
			errs[i] = ev.EvaluateRealtime(ctx, cveID)
		})
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("evaluator %d: %v", i, err)
		}
	}
	assertEventReopened(t, tdb.DB(), disp, ruleID, cveID, 2)
}

// TestActivationScanReopensResolvedEventSilently re-activates a rule whose resolved event
// matches again. The scan records a baseline, so the event reopens without a notification.
func TestActivationScanReopensResolvedEventSilently(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	disp := &mockDispatcher{}
	ev.SetDispatcher(disp)

	cveID := "CVE-2099-5200"
	ruleID := resolveThenReturn(t, ctx, tdb, ev, orgID, cveID)

	if err := tdb.SetAlertRuleStatus(ctx, orgID, ruleID, "activating"); err != nil {
		t.Fatalf("set rule activating: %v", err)
	}
	if err := ev.EvaluateActivation(ctx, ruleID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}

	assertEventReopened(t, tdb.DB(), disp, ruleID, cveID, 1)
	if !getSuppressDelivery(t, tdb.DB(), ruleID, cveID) {
		t.Error("suppress_delivery = false, want true so delivery recovery does not notify for the baseline")
	}
}
