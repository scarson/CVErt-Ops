// ABOUTME: Integration tests for package conditions in alert rules: correlation with ecosystem
// ABOUTME: conditions under "and", exact match after folding, and events resolving under the correlated reading.
package alert_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	cvePkgMixed      = "CVE-2026-30001" // npm foo and PyPI lodash
	cvePkgPyPIFooBar = "CVE-2026-30002"
	cvePkgNpmFooBar  = "CVE-2026-30003"
	cvePkgDebian13   = "CVE-2026-30004"
	cvePkgPyPILodash = "CVE-2026-30005"
	cvePkgNpmAB      = "CVE-2026-30006" // npm a and npm b
	cvePkgNpmA       = "CVE-2026-30007"
	cvePkgRejected   = "CVE-2026-30008" // npm lodash, rejected
	cvePkgNpmLodash  = "CVE-2026-30009"
	// Go lower-cases "İ" (U+0130) to "i" and a combining dot; a libc database's
	// lower() gives "i" alone. A rule must still match its own spelling.
	cvePkgHexNonASCII = "CVE-2026-30010"
)

var packageMatchCorpus = []struct {
	cveID    string
	packages []feed.AffectedPackage
}{
	{cvePkgMixed, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "foo"}, {Ecosystem: "PyPI", PackageName: "lodash"}}},
	{cvePkgPyPIFooBar, []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "foo-bar"}}},
	{cvePkgNpmFooBar, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "foo-bar"}}},
	{cvePkgDebian13, []feed.AffectedPackage{{Ecosystem: "Debian:13", PackageName: "openssl"}}},
	{cvePkgPyPILodash, []feed.AffectedPackage{{Ecosystem: "PyPI", PackageName: "lodash"}}},
	{cvePkgNpmAB, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "a"}, {Ecosystem: "npm", PackageName: "b"}}},
	{cvePkgNpmA, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "a"}}},
	{cvePkgRejected, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "lodash"}}},
	{cvePkgNpmLodash, []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "lodash"}}},
	{cvePkgHexNonASCII, []feed.AffectedPackage{{Ecosystem: "Hex", PackageName: "İzmir"}}},
}

// ingestPackageMatchCorpus runs every corpus CVE through the merge pipeline, and
// rejects cvePkgRejected through an NVD record, the status authority above OSV.
func ingestPackageMatchCorpus(t *testing.T, ctx context.Context, tdb *testutil.TestDB) {
	t.Helper()
	for _, row := range packageMatchCorpus {
		patch := feed.CanonicalPatch{CVEID: row.cveID, SourceID: row.cveID, AffectedPackages: row.packages}
		if err := merge.Ingest(ctx, tdb.Store, patch, "osv"); err != nil {
			t.Fatalf("merge.Ingest(%s): %v", row.cveID, err)
		}
	}
	rejected := feed.CanonicalPatch{CVEID: cvePkgRejected, SourceID: cvePkgRejected, Status: "Rejected"}
	if err := merge.Ingest(ctx, tdb.Store, rejected, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(%s, nvd): %v", cvePkgRejected, err)
	}

	// The rejected CVE keeps a row the rules below would match, so its exclusion is
	// the status filter's doing.
	var status string
	var rows int
	if err := tdb.DB().QueryRowContext(ctx, `
		SELECT c.status, (SELECT count(*) FROM cve_affected_packages cap
		                  WHERE cap.cve_id = c.cve_id AND cap.ecosystem = 'npm' AND cap.package_name = 'lodash')
		FROM cves c WHERE c.cve_id = $1`, cvePkgRejected).Scan(&status, &rows); err != nil {
		t.Fatalf("read %s: %v", cvePkgRejected, err)
	}
	if status != "Rejected" || rows != 1 {
		t.Fatalf("%s: status %q with %d npm lodash rows, want Rejected with 1", cvePkgRejected, status, rows)
	}
}

// assertPackageEventsOnly checks every corpus CVE: one event for each listed CVE, none for the rest.
func assertPackageEventsOnly(t *testing.T, db *sql.DB, ruleID uuid.UUID, want []string) {
	t.Helper()
	for _, row := range packageMatchCorpus {
		wantEvents := 0
		if slices.Contains(want, row.cveID) {
			wantEvents = 1
		}
		if n := countAlertEvents(t, db, ruleID, row.cveID); n != wantEvents {
			t.Errorf("%d events on %s (%v), want %d", n, row.cveID, row.packages, wantEvents)
		}
	}
}

func TestPackageMatch_RuleConditions(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	ingestPackageMatchCorpus(t, ctx, tdb)

	tests := []struct {
		name       string
		logic      string
		conditions string
		want       []string
	}{
		{
			"and: package and ecosystem on one row; a rejected CVE does not match", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]`,
			[]string{cvePkgNpmLodash},
		},
		{
			"or: each condition on its own", "or",
			`[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]`,
			[]string{cvePkgMixed, cvePkgNpmFooBar, cvePkgPyPILodash, cvePkgNpmAB, cvePkgNpmA, cvePkgNpmLodash},
		},
		{
			"and: the PyPI row matches", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"PyPI"},{"field":"affected.package","operator":"eq","value":"lodash"}]`,
			[]string{cvePkgMixed, cvePkgPyPILodash},
		},
		{
			"PyPI folds separators, npm does not", "and",
			`[{"field":"affected.package","operator":"eq","value":"Foo_Bar"}]`,
			[]string{cvePkgPyPIFooBar},
		},
		{
			"folding with both ecosystems named", "and",
			`[{"field":"affected.ecosystem","operator":"in","value":["npm","PyPI"]},{"field":"affected.package","operator":"in","value":["Foo_Bar"]}]`,
			[]string{cvePkgPyPIFooBar},
		},
		{
			"a base name covers its releases", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"Debian"},{"field":"affected.package","operator":"eq","value":"openssl"}]`,
			[]string{cvePkgDebian13},
		},
		{
			"a negative ecosystem is a condition on the whole CVE", "and",
			`[{"field":"affected.ecosystem","operator":"neq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]`,
			[]string{cvePkgPyPILodash},
		},
		{
			"package conditions are not correlated with each other", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"a"},{"field":"affected.package","operator":"eq","value":"b"}]`,
			[]string{cvePkgNpmAB},
		},
		{
			"substring match correlates too", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"contains","value":"lodash"}]`,
			[]string{cvePkgNpmLodash},
		},
		{
			"a non-ASCII name matches its own spelling, folded by the database", "and",
			`[{"field":"affected.package","operator":"eq","value":"İzmir"}]`,
			[]string{cvePkgHexNonASCII},
		},
		{
			"a non-ASCII name matches in a list with an ecosystem", "and",
			`[{"field":"affected.ecosystem","operator":"eq","value":"Hex"},{"field":"affected.package","operator":"in","value":["İZMIR"]}]`,
			[]string{cvePkgHexNonASCII},
		},
		{
			"a non-ASCII substring matches its own spelling", "and",
			`[{"field":"affected.package","operator":"starts_with","value":"İzm"}]`,
			[]string{cvePkgHexNonASCII},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Realtime: one candidate CVE at a time.
			rule := mustRule(t, ctx, tdb.Store, orgID, tt.logic, tt.conditions, nil)
			activateRule(t, ctx, tdb.Store, orgID, rule.ID)
			if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
				t.Fatalf("realtime rule status %q, want active", s)
			}
			for _, row := range packageMatchCorpus {
				if err := ev.EvaluateRealtime(ctx, row.cveID); err != nil {
					t.Fatalf("EvaluateRealtime(%s): %v", row.cveID, err)
				}
			}
			if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
				t.Fatalf("realtime rule status after evaluation %q, want active", s)
			}
			assertPackageEventsOnly(t, tdb.DB(), rule.ID, tt.want)

			// Activation: the whole corpus in candidate pages, the same answer.
			scan := createActivatingRule(t, ctx, tdb, orgID, tt.logic, tt.conditions)
			if err := ev.EvaluateActivation(ctx, scan.ID, orgID); err != nil {
				t.Fatalf("EvaluateActivation: %v", err)
			}
			if s := getRuleStatus(t, tdb.DB(), scan.ID); s != "active" {
				t.Fatalf("activation rule status %q, want active", s)
			}
			assertPackageEventsOnly(t, tdb.DB(), scan.ID, tt.want)
		})
	}
}

// createActivatingRule creates a rule in status activating, which EvaluateActivation
// scans and moves to active, and checks its status.
func createActivatingRule(t *testing.T, ctx context.Context, tdb *testutil.TestDB, orgID uuid.UUID, logic, conditions string) *store.AlertRuleRow {
	t.Helper()
	row, err := tdb.CreateAlertRule(ctx, orgID, store.CreateAlertRuleParams{
		Name:       "activation-" + uuid.New().String()[:8],
		Logic:      logic,
		Conditions: json.RawMessage(conditions),
		Status:     "activating",
	})
	if err != nil {
		t.Fatalf("create activating rule: %v", err)
	}
	t.Cleanup(func() {
		_ = tdb.SoftDeleteAlertRule(context.Background(), orgID, row.ID)
	})
	if s := getRuleStatus(t, tdb.DB(), row.ID); s != "activating" {
		t.Fatalf("rule status %q, want activating", s)
	}
	return row
}

// TestPackageMatch_EventsResolveUnderCorrelation pins design section 4.3: an event
// opened while an "and" rule's package and ecosystem conditions matched on different
// rows resolves when the CVE is next evaluated.
func TestPackageMatch_EventsResolveUnderCorrelation(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	ingestPackageMatchCorpus(t, ctx, tdb)

	var hash string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT material_hash FROM cves WHERE cve_id = $1`, cvePkgMixed).Scan(&hash); err != nil {
		t.Fatalf("read material_hash: %v", err)
	}

	// The npm row is foo and lodash is on the PyPI row: matched before correlation, not after.
	stale := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"contains","value":"lodash"}]`, nil)
	// Control: lodash is on the PyPI row, so this rule still matches.
	still := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"affected.ecosystem","operator":"eq","value":"PyPI"},{"field":"affected.package","operator":"contains","value":"lodash"}]`, nil)

	for _, rule := range []*store.AlertRuleRow{stale, still} {
		activateRule(t, ctx, tdb.Store, orgID, rule.ID)
		if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
			t.Fatalf("rule status %q, want active", s)
		}
		// An event opened under the uncorrelated reading, at the CVE's current hash.
		id, err := tdb.InsertAlertEvent(ctx, orgID, rule.ID, cvePkgMixed, hash, false)
		if err != nil || id == uuid.Nil {
			t.Fatalf("InsertAlertEvent: id %v, err %v", id, err)
		}
		if !getMatchState(t, tdb.DB(), rule.ID, cvePkgMixed) {
			t.Fatal("inserted event is not open")
		}
	}

	if err := ev.EvaluateRealtime(ctx, cvePkgMixed); err != nil {
		t.Fatalf("EvaluateRealtime: %v", err)
	}

	if getMatchState(t, tdb.DB(), stale.ID, cvePkgMixed) {
		t.Error("event of the npm rule is still open; want it resolved")
	}
	if !getMatchState(t, tdb.DB(), still.ID, cvePkgMixed) {
		t.Error("event of the PyPI rule was resolved; want it open")
	}
	for _, rule := range []*store.AlertRuleRow{stale, still} {
		if n := countAlertEvents(t, tdb.DB(), rule.ID, cvePkgMixed); n != 1 {
			t.Errorf("rule %s: %d events, want 1 (no new event at the same hash)", rule.ID, n)
		}
	}
}
