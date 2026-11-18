// ABOUTME: Integration tests that open alert events resolve when their CVE is rejected or withdrawn.
// ABOUTME: Retracts CVEs through the real merge pipeline and evaluates on the realtime, batch and EPSS paths.
package alert_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const criticalSeverityCondition = `[{"field":"severity","operator":"eq","value":"critical"}]`

// retractedStatuses holds each spelling of a retraction the feeds send: NVD, MITRE, and
// the withdrawn status the OSV and GHSA adapters set.
var retractedStatuses = []string{"Rejected", "REJECTED", "withdrawn"}

// ingestCritical runs an analyzed critical CVE through the merge pipeline.
func ingestCritical(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID string) {
	t.Helper()
	severity := "critical"
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
		CVEID:    cveID,
		Status:   "Analyzed",
		Severity: &severity,
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(active %s): %v", cveID, err)
	}
}

// ingestRetraction runs a rejection or withdrawal of the CVE through the merge pipeline.
// The record keeps its severity, so a rule on severity would still match it if the
// evaluator did not exclude retracted CVEs from matching.
func ingestRetraction(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID, status string) {
	t.Helper()
	severity := "critical"
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
		CVEID:       cveID,
		Status:      status,
		IsWithdrawn: true,
		Severity:    &severity,
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(retraction %s): %v", cveID, err)
	}
}

func assertEventOpen(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID string) {
	t.Helper()
	if n := countAlertEvents(t, db, ruleID, cveID); n != 1 {
		t.Fatalf("alert events before retraction = %d, want 1", n)
	}
	if !getMatchState(t, db, ruleID, cveID) {
		t.Fatal("last_match_state before retraction = false, want true")
	}
}

func assertEventResolved(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID string) {
	t.Helper()
	if getMatchState(t, db, ruleID, cveID) {
		t.Error("last_match_state after retraction = true, want false")
	}
	if n := countAlertEvents(t, db, ruleID, cveID); n != 1 {
		t.Errorf("alert events after retraction = %d, want 1 (a retracted CVE must not fire)", n)
	}
}

// TestRetractedCVEResolvesOpenEvent covers each evaluation path that resolves events.
// Timestamps are aged before the retraction, so only the retraction itself can bring
// the CVE back into a run's candidate set.
func TestRetractedCVEResolvesOpenEvent(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	for i, status := range retractedStatuses {
		t.Run("Batch/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2099-%04d", 1000+i)
			ingestCritical(t, ctx, tdb, cveID)
			rule := mustRule(t, ctx, tdb.Store, orgID, "and", criticalSeverityCondition, nil)
			activateRule(t, ctx, tdb.Store, orgID, rule.ID)

			if err := ev.EvaluateBatch(ctx); err != nil {
				t.Fatalf("EvaluateBatch before retraction: %v", err)
			}
			assertEventOpen(t, tdb.DB(), rule.ID, cveID)

			ageCorpus(t, ctx, tdb.DB())
			ingestRetraction(t, ctx, tdb, cveID, status)

			if err := ev.EvaluateBatch(ctx); err != nil {
				t.Fatalf("EvaluateBatch after retraction: %v", err)
			}
			assertEventResolved(t, tdb.DB(), rule.ID, cveID)
		})

		t.Run("Realtime/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2099-%04d", 2000+i)
			ingestCritical(t, ctx, tdb, cveID)
			rule := mustRule(t, ctx, tdb.Store, orgID, "and", criticalSeverityCondition, nil)
			activateRule(t, ctx, tdb.Store, orgID, rule.ID)

			if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
				t.Fatalf("EvaluateRealtime before retraction: %v", err)
			}
			assertEventOpen(t, tdb.DB(), rule.ID, cveID)

			ingestRetraction(t, ctx, tdb, cveID, status)

			if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
				t.Fatalf("EvaluateRealtime after retraction: %v", err)
			}
			assertEventResolved(t, tdb.DB(), rule.ID, cveID)
		})

		// EPSS-only rules are skipped by the realtime and batch paths, so the EPSS run is
		// the only one that can resolve their events. A tombstone does not touch
		// date_epss_updated, and the EPSS feed skips retracted CVEs afterwards.
		t.Run("EPSSOnly/"+status, func(t *testing.T) {
			cveID := fmt.Sprintf("CVE-2099-%04d", 3000+i)
			ruleID := openEPSSOnlyEvent(t, ctx, tdb, ev, orgID, cveID)

			ageCorpus(t, ctx, tdb.DB())
			ingestRetraction(t, ctx, tdb, cveID, status)

			if err := ev.EvaluateEPSS(ctx); err != nil {
				t.Fatalf("EvaluateEPSS after retraction: %v", err)
			}
			assertEventResolved(t, tdb.DB(), ruleID, cveID)
		})
	}

	// With no stored cursor the EPSS run selects CVEs that have a score, and a tombstone
	// has cleared this one's.
	t.Run("EPSSOnly/NoStoredCursor", func(t *testing.T) {
		cveID := "CVE-2099-4000"
		ruleID := openEPSSOnlyEvent(t, ctx, tdb, ev, orgID, cveID)

		ingestRetraction(t, ctx, tdb, cveID, "Rejected")
		if _, err := tdb.DB().ExecContext(ctx,
			`DELETE FROM feed_sync_state WHERE feed_name = 'alert:epss'`); err != nil {
			t.Fatalf("delete EPSS cursor: %v", err)
		}

		if err := ev.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS after retraction: %v", err)
		}
		assertEventResolved(t, tdb.DB(), ruleID, cveID)
	})
}

// openEPSSOnlyEvent scores a CVE above an EPSS-only rule's threshold and runs the EPSS
// path, leaving one open event. It returns the rule's ID.
func openEPSSOnlyEvent(t *testing.T, ctx context.Context, tdb *testutil.TestDB, ev *alert.Evaluator, orgID uuid.UUID, cveID string) uuid.UUID {
	t.Helper()
	ingestCritical(t, ctx, tdb, cveID)
	applyEPSSScore(t, ctx, tdb, cveID, 0.95)
	rule := mustEPSSRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"epss_score","operator":"gte","value":0.9}]`, true)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	if err := ev.EvaluateEPSS(ctx); err != nil {
		t.Fatalf("EvaluateEPSS before retraction: %v", err)
	}
	assertEventOpen(t, tdb.DB(), rule.ID, cveID)
	return rule.ID
}
