// ABOUTME: Integration tests for the re-check signal: a change to a rule match input outside material_hash
// ABOUTME: re-evaluates the CVE through realtime or batch, fires new matches once and never fires again.
package alert_test

import (
	"context"
	"database/sql"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	nodeProductCondition = `[{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}]`
	highSeverityCond     = `[{"field":"severity","operator":"eq","value":"high"}]`
)

// recheckFixture is one org evaluated as the application role with a recording dispatcher.
type recheckFixture struct {
	tdb        *testutil.TestDB
	db         *sql.DB
	orgID      uuid.UUID
	evaluator  *alert.Evaluator
	dispatcher *mockDispatcher
}

func newRecheckFixture(t *testing.T) *recheckFixture {
	t.Helper()
	tdb := testutil.NewTestDB(t)
	dispatcher := &mockDispatcher{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	evaluator := alert.New(tdb.AppStore.DB(), tdb.AppStore, alert.NewRuleCache(), log, 0)
	evaluator.SetDispatcher(dispatcher)
	return &recheckFixture{
		tdb: tdb, db: tdb.DB(), orgID: createTestOrg(t, tdb.DB()),
		evaluator: evaluator, dispatcher: dispatcher,
	}
}

func (f *recheckFixture) activeRule(t *testing.T, ctx context.Context, conditions string) *store.AlertRuleRow {
	t.Helper()
	rule := mustRule(t, ctx, f.tdb.Store, f.orgID, "and", conditions, nil)
	activateRule(t, ctx, f.tdb.Store, f.orgID, rule.ID)
	return rule
}

// mergeAndEvaluate merges patch through st and applies the ingest handler's rule: read
// both change hashes before and after the merge, and run realtime evaluation only when
// they differ. It returns the two readings, so a test asserts whether realtime ran.
func (f *recheckFixture) mergeAndEvaluate(t *testing.T, ctx context.Context, st merge.Store, patch feed.CanonicalPatch, source string) (before, after store.CVEChangeHashes) {
	t.Helper()
	before, err := f.tdb.GetCVEChangeHashes(ctx, patch.CVEID)
	if err != nil {
		t.Fatalf("GetCVEChangeHashes before merge: %v", err)
	}
	if err := merge.Ingest(ctx, st, patch, source); err != nil {
		t.Fatalf("merge.Ingest(%s, %s): %v", patch.CVEID, source, err)
	}
	after, err = f.tdb.GetCVEChangeHashes(ctx, patch.CVEID)
	if err != nil {
		t.Fatalf("GetCVEChangeHashes after merge: %v", err)
	}
	if before != after {
		if err := f.evaluator.EvaluateRealtime(ctx, patch.CVEID); err != nil {
			t.Fatalf("EvaluateRealtime(%s): %v", patch.CVEID, err)
		}
	}
	return before, after
}

func (f *recheckFixture) fanouts(ruleID uuid.UUID, cveID string) int {
	f.dispatcher.mu.Lock()
	defer f.dispatcher.mu.Unlock()
	n := 0
	for _, call := range f.dispatcher.calls {
		if call.ruleID == ruleID && call.cveID == cveID {
			n++
		}
	}
	return n
}

// requireMatchInputsOnlyChange fails unless the merge moved match_inputs_hash and left
// material_hash alone, which is the change under test and the reason realtime ran.
func requireMatchInputsOnlyChange(t *testing.T, before, after store.CVEChangeHashes) {
	t.Helper()
	if after.Material == "" || after.Material != before.Material {
		t.Fatalf("material_hash %q -> %q, want unchanged and set", before.Material, after.Material)
	}
	if after.MatchInputs == "" || after.MatchInputs == before.MatchInputs {
		t.Fatalf("match_inputs_hash %q -> %q, want a new value", before.MatchInputs, after.MatchInputs)
	}
}

func dateModified(t *testing.T, ctx context.Context, db *sql.DB, cveID string) time.Time {
	t.Helper()
	var d time.Time
	if err := db.QueryRowContext(ctx, `SELECT date_modified_canonical FROM cves WHERE cve_id = $1`, cveID).Scan(&d); err != nil {
		t.Fatalf("read date_modified_canonical of %s: %v", cveID, err)
	}
	return d
}

func mitreCNA(cveID string, cna ...feed.CNAAffected) feed.CanonicalPatch {
	high := "HIGH"
	return feed.CanonicalPatch{CVEID: cveID, Status: "Published", Severity: &high, CNAAffected: cna}
}

// TestRecheck_CNAProductChangeAloneRunsRealtime: a CNA correcting n/a to Node.js moves
// only match_inputs_hash. Realtime runs, the Node rule fires once, and a rule that had
// already fired at this material_hash does not fire again.
func TestRecheck_CNAProductChangeAloneRunsRealtime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecheckFixture(t)
	const cveID = "CVE-2026-32001"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)
	sevRule := f.activeRule(t, ctx, highSeverityCond)

	before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "n/a"}), "mitre")
	if before == after {
		t.Fatal("a new CVE left both change hashes as they were; realtime did not run")
	}
	if n := countAlertEvents(t, f.db, sevRule.ID, cveID); n != 1 || f.fanouts(sevRule.ID, cveID) != 1 {
		t.Fatalf("severity rule: %d events, %d notifications, want 1 and 1", n, f.fanouts(sevRule.ID, cveID))
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 0 {
		t.Fatalf("Node rule: %d events while the CNA product is n/a, want 0", n)
	}
	modifiedBefore := dateModified(t, ctx, f.db, cveID)

	before, after = f.mergeAndEvaluate(t, ctx, f.tdb.Store, mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "Node.js"}), "mitre")
	requireMatchInputsOnlyChange(t, before, after)
	if got := dateModified(t, ctx, f.db, cveID); !got.Equal(modifiedBefore) {
		t.Errorf("date_modified_canonical moved: %v -> %v", modifiedBefore, got)
	}
	if n := countAlertEventsAt(t, f.db, nodeRule.ID, cveID, after.Material); n != 1 {
		t.Errorf("Node rule: %d events at the current material_hash, want 1", n)
	}
	if n := f.fanouts(nodeRule.ID, cveID); n != 1 {
		t.Errorf("Node rule: %d notifications, want 1", n)
	}
	if n := countAlertEvents(t, f.db, sevRule.ID, cveID); n != 1 {
		t.Errorf("severity rule: %d events, want 1 (its match did not change)", n)
	}
	if n := f.fanouts(sevRule.ID, cveID); n != 1 {
		t.Errorf("severity rule: %d notifications, want 1 (no new notification)", n)
	}
}

// TestRecheck_VulnerableFlagFlipRunsRealtime: NVD marking a nodejs:node.js match
// vulnerable moves only match_inputs_hash, and the Node rule fires once.
func TestRecheck_VulnerableFlagFlipRunsRealtime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecheckFixture(t)
	const cveID = "CVE-2026-32002"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)
	sevRule := f.activeRule(t, ctx, highSeverityCond)

	nodeCPE := cpe23("nodejs:node.js")
	high := "HIGH"
	nvd := func(vulnerable bool) feed.CanonicalPatch {
		return feed.CanonicalPatch{
			CVEID: cveID, Status: "Analyzed", Severity: &high,
			CPEMatches:   []feed.CPEMatch{{CPE: nodeCPE, CPENormalized: nodeCPE, Vulnerable: vulnerable}},
			AffectedCPEs: []feed.AffectedCPE{{CPE: nodeCPE, CPENormalized: nodeCPE}},
		}
	}

	if before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, nvd(false), "nvd"); before == after {
		t.Fatal("a new CVE left both change hashes as they were; realtime did not run")
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 0 {
		t.Fatalf("Node rule: %d events while the match is not vulnerable, want 0", n)
	}
	if n := countAlertEvents(t, f.db, sevRule.ID, cveID); n != 1 {
		t.Fatalf("severity rule: %d events, want 1", n)
	}
	modifiedBefore := dateModified(t, ctx, f.db, cveID)

	before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, nvd(true), "nvd")
	requireMatchInputsOnlyChange(t, before, after)
	if got := dateModified(t, ctx, f.db, cveID); !got.Equal(modifiedBefore) {
		t.Errorf("date_modified_canonical moved: %v -> %v", modifiedBefore, got)
	}
	if n := countAlertEventsAt(t, f.db, nodeRule.ID, cveID, after.Material); n != 1 {
		t.Errorf("Node rule: %d events at the current material_hash, want 1", n)
	}
	if n := f.fanouts(nodeRule.ID, cveID); n != 1 {
		t.Errorf("Node rule: %d notifications, want 1", n)
	}
	if n, sent := countAlertEvents(t, f.db, sevRule.ID, cveID), f.fanouts(sevRule.ID, cveID); n != 1 || sent != 1 {
		t.Errorf("severity rule: %d events, %d notifications, want 1 and 1", n, sent)
	}
}

// TestRecheck_BatchEvaluatesSkippedRealtime: when realtime evaluation of a match-inputs
// change does not happen, the next batch run finds the CVE through
// date_match_inputs_changed alone and fires the rule.
func TestRecheck_BatchEvaluatesSkippedRealtime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecheckFixture(t)
	const cveID = "CVE-2026-32003"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)

	if err := merge.Ingest(ctx, f.tdb.Store, mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "n/a"}), "mitre"); err != nil {
		t.Fatalf("merge.Ingest: %v", err)
	}
	// A first run leaves a non-zero cursor; a zero cursor would scan every CVE.
	if err := f.evaluator.EvaluateBatch(ctx); err != nil {
		t.Fatalf("first EvaluateBatch: %v", err)
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 0 {
		t.Fatalf("Node rule: %d events while the CNA product is n/a, want 0", n)
	}
	cursor := getCursorSince(t, f.db, "alert:batch")
	if cursor.IsZero() {
		t.Fatal("batch cursor is zero after the first run")
	}
	ageCorpus(t, ctx, f.db)

	// The CNA-only change, merged without the realtime evaluation the handler would run.
	before, err := f.tdb.GetCVEChangeHashes(ctx, cveID)
	if err != nil {
		t.Fatalf("GetCVEChangeHashes: %v", err)
	}
	if err := merge.Ingest(ctx, f.tdb.Store, mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "Node.js"}), "mitre"); err != nil {
		t.Fatalf("merge.Ingest: %v", err)
	}
	after, err := f.tdb.GetCVEChangeHashes(ctx, cveID)
	if err != nil {
		t.Fatalf("GetCVEChangeHashes: %v", err)
	}
	requireMatchInputsOnlyChange(t, before, after)
	// Only date_match_inputs_changed can bring the CVE into the next run.
	if modified := dateModified(t, ctx, f.db, cveID); !modified.Before(cursor.Add(-2 * time.Minute)) {
		t.Fatalf("date_modified_canonical %v is inside the batch rescan window of cursor %v", modified, cursor)
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 0 {
		t.Fatalf("Node rule: %d events before the batch run, want 0", n)
	}

	if err := f.evaluator.EvaluateBatch(ctx); err != nil {
		t.Fatalf("second EvaluateBatch: %v", err)
	}
	if n := countAlertEventsAt(t, f.db, nodeRule.ID, cveID, after.Material); n != 1 {
		t.Errorf("Node rule: %d events at the current material_hash after the batch run, want 1", n)
	}
	if n := f.fanouts(nodeRule.ID, cveID); n != 1 {
		t.Errorf("Node rule: %d notifications, want 1", n)
	}
}

// TestRecheck_CaseOnlyCopyDoesNotChangeMatchInputs: NVD relaying the CNA record with
// names that differ only in ASCII case is no change to the match inputs.
func TestRecheck_CaseOnlyCopyDoesNotChangeMatchInputs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecheckFixture(t)
	const cveID = "CVE-2026-32004"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)

	f.mergeAndEvaluate(t, ctx, f.tdb.Store, mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "Node.js"}), "mitre")
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 1 {
		t.Fatalf("Node rule: %d events, want 1", n)
	}
	stamp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := f.db.ExecContext(ctx, `UPDATE cves SET date_match_inputs_changed = $2 WHERE cve_id = $1`, cveID, stamp); err != nil {
		t.Fatalf("set date_match_inputs_changed: %v", err)
	}

	nvd := mitreCNA(cveID, feed.CNAAffected{Vendor: "NODE.JS", Product: "node.js"})
	before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, nvd, "nvd")
	var copies int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM cve_cna_affected WHERE cve_id = $1`, cveID).Scan(&copies); err != nil {
		t.Fatalf("count CNA rows: %v", err)
	}
	if copies != 2 {
		t.Fatalf("cve_cna_affected has %d rows, want both copies (2)", copies)
	}
	if before != after {
		t.Errorf("change hashes %+v -> %+v, want unchanged (no realtime run)", before, after)
	}
	var changed time.Time
	if err := f.db.QueryRowContext(ctx, `SELECT date_match_inputs_changed FROM cves WHERE cve_id = $1`, cveID).Scan(&changed); err != nil {
		t.Fatalf("read date_match_inputs_changed: %v", err)
	}
	if !changed.Equal(stamp) {
		t.Errorf("date_match_inputs_changed = %v, want exactly %v", changed, stamp)
	}
	if n, sent := countAlertEvents(t, f.db, nodeRule.ID, cveID), f.fanouts(nodeRule.ID, cveID); n != 1 || sent != 1 {
		t.Errorf("Node rule: %d events, %d notifications, want 1 and 1", n, sent)
	}
}

// TestRecheck_NullStoredHashRechecksOnceWithoutDuplicate: a CVE merged before
// match_inputs_hash existed is re-checked on its next merge, once, and its existing
// alert is not sent again.
func TestRecheck_NullStoredHashRechecksOnceWithoutDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRecheckFixture(t)
	const cveID = "CVE-2026-32005"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)
	patch := mitreCNA(cveID, feed.CNAAffected{Vendor: "Node.js", Product: "Node.js"})

	f.mergeAndEvaluate(t, ctx, f.tdb.Store, patch, "mitre")
	if n, sent := countAlertEvents(t, f.db, nodeRule.ID, cveID), f.fanouts(nodeRule.ID, cveID); n != 1 || sent != 1 {
		t.Fatalf("Node rule: %d events, %d notifications, want 1 and 1", n, sent)
	}
	// A column on an existing row, as a CVE merged before the column existed has.
	if _, err := f.db.ExecContext(ctx, `UPDATE cves SET match_inputs_hash = NULL WHERE cve_id = $1`, cveID); err != nil {
		t.Fatalf("clear match_inputs_hash: %v", err)
	}

	before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, patch, "mitre")
	if before.MatchInputs != "" {
		t.Fatalf("match_inputs_hash before the merge = %q, want empty (NULL)", before.MatchInputs)
	}
	requireMatchInputsOnlyChange(t, before, after)
	if n, sent := countAlertEvents(t, f.db, nodeRule.ID, cveID), f.fanouts(nodeRule.ID, cveID); n != 1 || sent != 1 {
		t.Errorf("Node rule after the re-check: %d events, %d notifications, want 1 and 1 (no duplicate)", n, sent)
	}

	// Once: the next merge of the same inputs changes neither hash.
	if before, after := f.mergeAndEvaluate(t, ctx, f.tdb.Store, patch, "mitre"); before != after {
		t.Errorf("second merge: change hashes %+v -> %+v, want unchanged", before, after)
	}
}

// TestRecheck_LateBindingProductRuleMatchesNewID: after a native advisory ID is promoted
// to its CVE ID, the CNA rows are under the new ID and a product rule matches it.
func TestRecheck_LateBindingProductRuleMatchesNewID(t *testing.T) {
	ctx := context.Background()
	f := newRecheckFixture(t)
	const native, cveID = "GHSA-recheck-move", "CVE-2026-32006"
	nodeRule := f.activeRule(t, ctx, nodeProductCondition)
	cna := []feed.CNAAffected{{Vendor: "Node.js", Product: "Node.js"}}

	f.mergeAndEvaluate(t, ctx, f.tdb.Store, feed.CanonicalPatch{CVEID: native, SourceID: native, CNAAffected: cna}, "osv")
	if n := countAlertEvents(t, f.db, nodeRule.ID, native); n != 1 {
		t.Fatalf("Node rule: %d events under the native ID, want 1", n)
	}

	// The promotion runs as the application role, as late_binding_test.go does.
	if before, after := f.mergeAndEvaluate(t, ctx, f.tdb.AppStore,
		feed.CanonicalPatch{CVEID: cveID, SourceID: native, CNAAffected: cna}, "osv"); before == after {
		t.Fatalf("change hashes of %s unchanged by the promotion (%+v); realtime did not run", cveID, after)
	}
	for id, want := range map[string]int{native: 0, cveID: 1} {
		var n int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM cve_cna_affected WHERE cve_id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("count CNA rows of %s: %v", id, err)
		}
		if n != want {
			t.Errorf("%s has %d CNA rows, want %d", id, n, want)
		}
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, native); n != 0 {
		t.Errorf("Node rule: %d events remain under the native ID, want 0", n)
	}
	if n := countAlertEvents(t, f.db, nodeRule.ID, cveID); n != 1 {
		t.Errorf("Node rule: %d events under %s, want 1 (the moved event)", n, cveID)
	}
	if n := f.fanouts(nodeRule.ID, cveID); n != 0 {
		t.Errorf("Node rule: %d notifications for the moved event, want 0", n)
	}

	// A product rule that did not exist before the move matches the new ID.
	newRule := f.activeRule(t, ctx, nodeProductCondition)
	if err := f.evaluator.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime(%s): %v", cveID, err)
	}
	if n := countAlertEvents(t, f.db, newRule.ID, cveID); n != 1 {
		t.Errorf("new product rule: %d events under %s, want 1", n, cveID)
	}
}
