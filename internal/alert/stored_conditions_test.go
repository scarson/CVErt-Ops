// ABOUTME: Integration tests for stored alert-rule conditions holding keys the DSL does not define.
// ABOUTME: Such a rule must fail closed (status=error, no alert events) instead of matching without the key.
package alert_test

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestEvaluateBatch_StoredConditionWithUnknownKeyFailsClosed checks that a rule
// whose stored conditions hold a key the DSL does not define, or a known key in
// another case, is set to status=error and produces no alert events. Read
// without the key, such a rule would match CVEs its author did not ask for:
// "negate" was meant to invert the condition. The rules are written through the
// store, which bypasses the API's validation as a row written before it would.
func TestEvaluateBatch_StoredConditionWithUnknownKeyFailsClosed(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	testutil.SeedCorpus(t, tdb)
	orgID := createTestOrg(t, tdb.DB())

	var wantControlEvents int
	if err := tdb.DB().QueryRowContext(ctx, `
		SELECT count(*) FROM cves
		 WHERE lower(severity) = 'critical'
		   AND COALESCE(lower(status), '') NOT IN ('rejected', 'withdrawn')`,
	).Scan(&wantControlEvents); err != nil {
		t.Fatalf("count critical CVEs in corpus: %v", err)
	}
	if wantControlEvents == 0 {
		t.Fatal("corpus has no critical CVEs; the control rule would prove nothing")
	}

	control := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"severity","operator":"in","value":["critical"]}]`, nil)
	unknownKey := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"severity","operator":"in","value":["critical"],"negate":true}]`, nil)
	caseVariant := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"Field":"severity","operator":"in","value":["critical"]}]`, nil)
	for _, id := range []uuid.UUID{control.ID, unknownKey.ID, caseVariant.ID} {
		activateRule(t, ctx, tdb.Store, orgID, id)
	}

	ev, logBuf := newLoggedEvaluator(tdb, tdb.Store)
	if err := ev.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
	// A rule set to error is not a rule that failed to evaluate: it does not
	// hold the batch cursor back for the other rules.
	if held := getCursorHeldRuns(t, tdb.DB(), "alert:batch"); held != 0 {
		t.Errorf("batch cursor held_runs = %d, want 0", held)
	}

	if s := getRuleStatus(t, tdb.DB(), control.ID); s != "active" {
		t.Errorf("control rule status = %q, want active", s)
	}
	if n := countRuleEvents(t, ctx, tdb, control.ID); n != wantControlEvents {
		t.Errorf("control rule alert_events = %d, want %d (one per critical CVE)", n, wantControlEvents)
	}

	logged := logBuf.String()
	for _, tc := range []struct {
		name   string
		ruleID uuid.UUID
		key    string
	}{
		{"unknown key", unknownKey.ID, "negate"},
		{"case-variant key", caseVariant.ID, "Field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if s := getRuleStatus(t, tdb.DB(), tc.ruleID); s != "error" {
				t.Errorf("rule status = %q, want error", s)
			}
			if n := countRuleEvents(t, ctx, tdb, tc.ruleID); n != 0 {
				t.Errorf("rule alert_events = %d, want 0", n)
			}
			wantLog := `unknown key \"` + tc.key + `\" in conditions[0]`
			if !strings.Contains(logged, "rule_id="+tc.ruleID.String()) || !strings.Contains(logged, wantLog) {
				t.Errorf("want the rule ID and %s logged, got log %q", wantLog, logged)
			}
		})
	}
	// The failure is logged by key and rule ID; condition values stay out of the log.
	if strings.Contains(logged, "critical") {
		t.Errorf("log holds a condition value: %q", logged)
	}
}

// countRuleEvents returns the number of alert_events for a rule across all CVEs.
func countRuleEvents(t *testing.T, ctx context.Context, tdb *testutil.TestDB, ruleID uuid.UUID) int {
	t.Helper()
	var n int
	if err := tdb.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM alert_events WHERE rule_id = $1`, ruleID,
	).Scan(&n); err != nil {
		t.Fatalf("count alert_events for rule %s: %v", ruleID, err)
	}
	return n
}
