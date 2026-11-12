// ABOUTME: Tests one advisory's verdict from its cve_cpe_matches rows for one product version.
// ABOUTME: Covers each row rule of design section 4.2, the combining rule, fix candidates and the work meter.
package check

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/scarson/cvert-ops/internal/version"
)

// CPE strings as the NVD adapter stores them in cpe_normalized: the criteria
// string, lower-cased.
const (
	cpeNodeAny     = "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
	cpeNodeNA      = "cpe:2.3:a:nodejs:node.js:-:*:*:*:*:*:*:*"
	cpeProduct123  = "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"
	cpeDotnetPrev1 = "cpe:2.3:a:microsoft:.net:11.0.0:preview1:*:*:*:*:*:*"
	cpeEscapedFoo  = `cpe:2.3:a:foo\:bar:product:1.2.3:*:*:*:*:*:*:*`
)

// cpeBounds holds a row's four NVD bounds; an absent bound is "".
type cpeBounds struct {
	startIncluding, startExcluding, endIncluding, endExcluding string
}

func cpeRow(cpe string, b cpeBounds) CPERow {
	return CPERow{
		CVEID: "CVE-2026-0001", CPE: cpe,
		VersionStartIncluding: b.startIncluding, VersionStartExcluding: b.startExcluding,
		VersionEndIncluding: b.endIncluding, VersionEndExcluding: b.endExcluding,
	}
}

func matchedCPE(cpe, introduced, fixed, lastAffected string) Matched {
	return Matched{Evidence: "nvd_cpe", CPE: cpe, Introduced: introduced, Fixed: fixed, LastAffected: lastAffected}
}

func evaluateCPE(t *testing.T, ver string, rows []CPERow) Outcome {
	t.Helper()
	m := newWorkMeter(context.Background())
	got := EvaluateCPERows(m, ver, rows, 0)
	if err := m.Err(); err != nil {
		t.Fatalf("meter error after evaluation: %v", err)
	}
	return got
}

func TestEvaluateCPERows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		version    string
		rows       []CPERow
		want       Outcome // Ranges is compared through wantRanges
		wantRanges []version.Range
	}{
		// Design 4.2, row "version component * with any versionStart* or versionEnd*".
		{
			name: "versionEndExcluding is the fixed bound", version: "24.22.0",
			rows: []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "24.0.0", endExcluding: "24.22.1"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE(cpeNodeAny, "24.0.0", "24.22.1", "")},
				Candidates: []string{"24.22.1"}},
			wantRanges: []version.Range{{Introduced: "24.0.0", Fixed: "24.22.1"}},
		},
		{
			name: "versionEndExcluding itself is not affected", version: "24.22.1",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "24.0.0", endExcluding: "24.22.1"})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "24.0.0", Fixed: "24.22.1"}},
		},
		{
			name: "version below versionStartIncluding is not affected", version: "23.9.0",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "24.0.0", endExcluding: "24.22.1"})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "24.0.0", Fixed: "24.22.1"}},
		},
		{
			name: "versionEndIncluding is the last affected version and no start means 0", version: "2.5.0",
			rows: []CPERow{cpeRow(cpeNodeAny, cpeBounds{endIncluding: "2.5.0"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeNodeAny, "0", "", "2.5.0")}},
			wantRanges: []version.Range{{Introduced: "0", LastAffected: "2.5.0"}},
		},
		{
			name: "version after versionEndIncluding is not affected", version: "2.5.1",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{endIncluding: "2.5.0"})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", LastAffected: "2.5.0"}},
		},
		{
			name: "start bound only is affected from the start on", version: "9.0",
			rows: []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "3.0"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeNodeAny, "3.0", "", "")}},
			wantRanges: []version.Range{{Introduced: "3.0"}},
		},
		{
			name: "empty version component with bounds reads as *", version: "1.5",
			rows: []CPERow{cpeRow("cpe:2.3:a:vendor:product::*:*:*:*:*:*:*", cpeBounds{endExcluding: "2.0"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE("cpe:2.3:a:vendor:product::*:*:*:*:*:*:*", "0", "2.0", "")},
				Candidates: []string{"2.0"}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0"}},
		},

		// Design 4.2, row "versionStartExcluding": stored as an inclusive Introduced.
		{
			name: "versionStartExcluding reports its own version affected", version: "1.0.0",
			rows: []CPERow{cpeRow(cpeNodeAny, cpeBounds{startExcluding: "1.0.0", endExcluding: "2.0.0"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE(cpeNodeAny, "1.0.0", "2.0.0", "")},
				Candidates: []string{"2.0.0"}},
			wantRanges: []version.Range{{Introduced: "1.0.0", Fixed: "2.0.0"}},
		},
		{
			name: "version below versionStartExcluding is not affected", version: "0.9.0",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startExcluding: "1.0.0", endExcluding: "2.0.0"})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "1.0.0", Fixed: "2.0.0"}},
		},

		// Design 4.2, row "a literal version component and no range".
		{
			name: "literal version component is affected at that version", version: "1.2.3",
			rows: []CPERow{cpeRow(cpeProduct123, cpeBounds{})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeProduct123, "1.2.3", "", "1.2.3")}},
			wantRanges: []version.Range{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
		},
		{
			name: "literal version component does not affect the next version", version: "1.2.4",
			rows:       []CPERow{cpeRow(cpeProduct123, cpeBounds{})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
		},
		{
			name: "update component does not narrow the row: .net 11.0.0 preview1 affects 11.0.0", version: "11.0.0",
			rows: []CPERow{cpeRow(cpeDotnetPrev1, cpeBounds{})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeDotnetPrev1, "11.0.0", "", "11.0.0")}},
			wantRanges: []version.Range{{Introduced: "11.0.0", LastAffected: "11.0.0"}},
		},
		{
			name: "escaped colon in the vendor still reads the version component", version: "1.2.3",
			rows: []CPERow{cpeRow(cpeEscapedFoo, cpeBounds{})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeEscapedFoo, "1.2.3", "", "1.2.3")}},
			wantRanges: []version.Range{{Introduced: "1.2.3", LastAffected: "1.2.3"}},
		},

		// Design 4.2, row "version component * with no bounds, or -".
		{
			name: "* with no bounds is no_version_bounds", version: "1.0",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds},
			wantRanges: []version.Range{{}},
		},
		{
			name: "- with no bounds is no_version_bounds", version: "1.0",
			rows:       []CPERow{cpeRow(cpeNodeNA, cpeBounds{})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds},
			wantRanges: []version.Range{{}},
		},
		{
			name: "- with bounds is no_version_bounds", version: "1.0",
			rows:       []CPERow{cpeRow(cpeNodeNA, cpeBounds{startIncluding: "0.5", endExcluding: "2.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds},
			wantRanges: []version.Range{{}},
		},

		// Rows the design's table does not describe: cannot evaluate, never a guess.
		{
			name: "both start bounds is invalid_range", version: "1.5",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0", startExcluding: "1.0", endExcluding: "2.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},
		{
			name: "both end bounds is invalid_range", version: "1.5",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{endIncluding: "2.0", endExcluding: "2.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0", LastAffected: "2.0"}},
		},
		{
			name: "literal version component with bounds is invalid_range", version: "1.2.3",
			rows:       []CPERow{cpeRow(cpeProduct123, cpeBounds{endExcluding: "2.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},
		{
			name: "CPE with fewer than 13 components is invalid_range", version: "1.2.3",
			rows:       []CPERow{cpeRow("cpe:2.3:a:vendor:product:1.2.3", cpeBounds{})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},
		{
			name: "CPE with more than 13 components is invalid_range", version: "1.2.3",
			rows:       []CPERow{cpeRow(cpeProduct123+":*", cpeBounds{})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{}},
		},
		{
			name: "literal version component that is not dotted numbers is invalid_range", version: "1.2.3",
			rows:       []CPERow{cpeRow("cpe:2.3:a:vendor:product:1.2.3rc1:*:*:*:*:*:*:*", cpeBounds{})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Introduced: "1.2.3rc1", LastAffected: "1.2.3rc1"}},
		},
		// Design 4.2, bounds that are not dotted numbers: compared by their
		// leading dotted numbers where those differ.
		{
			name: "literal version that is not dotted numbers, other leading numbers, is not affected", version: "8.4.14",
			rows:       []CPERow{cpeRow("cpe:2.3:a:php:php:2.0b10:*:*:*:*:*:*:*", cpeBounds{})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "2.0b10", LastAffected: "2.0b10"}},
		},
		{
			name: "fix bound that is not dotted numbers, version past it, is not affected", version: "3.5.4",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.0.2zf"})},
			want:       Outcome{Verdict: NotAffected, Comparable: true},
			wantRanges: []version.Range{{Introduced: "1.0.0", Fixed: "1.0.2zf"}},
		},
		{
			name: "fix bound that is not dotted numbers, version inside, is affected", version: "1.0.1",
			rows: []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.0.2zf"})},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE(cpeNodeAny, "1.0.0", "1.0.2zf", "")},
				Candidates: []string{"1.0.2zf"}},
			wantRanges: []version.Range{{Introduced: "1.0.0", Fixed: "1.0.2zf"}},
		},
		{
			name: "fix bound that is not dotted numbers, version on its leading numbers, is invalid_range", version: "1.0.2",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.0.2zf"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange},
			wantRanges: []version.Range{{Introduced: "1.0.0", Fixed: "1.0.2zf"}},
		},

		// Design 4.2: a version that is not dotted numbers cannot be evaluated.
		{
			name: "release candidate version is invalid_version", version: "1.24rc1",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0"}},
		},
		{
			name: "release candidate version is invalid_version whichever row comes first", version: "1.24rc1",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{}),
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"}),
			},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{}, {Introduced: "0", Fixed: "2.0"}},
		},
		{
			name: "distro version is invalid_version", version: "8.5.4-0ubuntu1.4",
			rows:       []CPERow{cpeRow(cpeNodeAny, cpeBounds{endExcluding: "9.0"})},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidVersion, InvalidVersion: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "9.0"}},
		},

		// Combining the rows of one advisory (design 4.1's rule).
		{
			name: "one affected row among not affected rows is affected", version: "1.5",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "1.0"}),
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0", endExcluding: "2.0"}),
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "3.0", endExcluding: "4.0"}),
			},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE(cpeNodeAny, "1.0", "2.0", "")},
				Candidates: []string{"2.0"}},
			wantRanges: []version.Range{
				{Introduced: "0", Fixed: "1.0"},
				{Introduced: "1.0", Fixed: "2.0"},
				{Introduced: "3.0", Fixed: "4.0"},
			},
		},
		{
			name: "affected beside a no_version_bounds row is affected", version: "1.5",
			rows: []CPERow{
				cpeRow(cpeNodeNA, cpeBounds{}),
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"}),
			},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched:    []Matched{matchedCPE(cpeNodeAny, "0", "2.0", "")},
				Candidates: []string{"2.0"}},
			wantRanges: []version.Range{{}, {Introduced: "0", Fixed: "2.0"}},
		},
		{
			name: "not affected beside a no_version_bounds row is no_version_bounds", version: "2.5",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"}),
				cpeRow(cpeNodeAny, cpeBounds{}),
			},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0"}, {}},
		},
		{
			name: "cannot evaluate takes the reason of the first row that cannot be compared", version: "2.5",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"}),
				cpeRow(cpeProduct123, cpeBounds{endExcluding: "2.0"}),
				cpeRow(cpeNodeAny, cpeBounds{}),
			},
			want:       Outcome{Verdict: CannotEvaluate, Reason: ReasonInvalidRange, Comparable: true},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "2.0"}, {}, {}},
		},
		{
			name: "versionEndIncluding is not a fix candidate", version: "1.5",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0", endIncluding: "1.9"}),
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0", endExcluding: "2.0"}),
			},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{
					matchedCPE(cpeNodeAny, "1.0", "", "1.9"),
					matchedCPE(cpeNodeAny, "1.0", "2.0", ""),
				},
				Candidates: []string{"2.0"}},
			wantRanges: []version.Range{
				{Introduced: "1.0", LastAffected: "1.9"},
				{Introduced: "1.0", Fixed: "2.0"},
			},
		},
		{
			name: "versionEndExcluding of a row that does not contain the version is not a candidate", version: "1.5",
			rows: []CPERow{
				cpeRow(cpeNodeAny, cpeBounds{endExcluding: "1.0"}),
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0", endIncluding: "1.9"}),
			},
			want: Outcome{Verdict: Affected, Comparable: true,
				Matched: []Matched{matchedCPE(cpeNodeAny, "1.0", "", "1.9")}},
			wantRanges: []version.Range{{Introduced: "0", Fixed: "1.0"}, {Introduced: "1.0", LastAffected: "1.9"}},
		},
		{
			name: "no rows cannot be evaluated", version: "1.0",
			want: Outcome{Verdict: CannotEvaluate},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := evaluateCPE(t, tt.version, tt.rows)
			gotRanges := boundRanges(got.Ranges)
			for i, b := range got.Ranges {
				if b.Check == nil {
					t.Errorf("Ranges[%d].Check is nil", i)
				}
			}
			got.Ranges = nil
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("EvaluateCPERows(%q) =\n  %+v\nwant\n  %+v", tt.version, got, tt.want)
			}
			if !reflect.DeepEqual(gotRanges, tt.wantRanges) {
				t.Errorf("Ranges = %+v, want %+v", gotRanges, tt.wantRanges)
			}
		})
	}
}

// TestEvaluateCPERowsBoundOrder checks that every Bound reads candidates with
// CheckProduct, which requires a dotted-number version, and that a row with no
// version bounds answers cannot evaluate for any candidate, so fix reporting
// never clears a candidate against it.
func TestEvaluateCPERowsBoundOrder(t *testing.T) {
	t.Parallel()
	got := evaluateCPE(t, "1.5", []CPERow{
		cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"}),
		cpeRow(cpeNodeAny, cpeBounds{}),
		cpeRow(cpeNodeNA, cpeBounds{}),
	})
	if len(got.Ranges) != 3 {
		t.Fatalf("len(Ranges) = %d, want 3", len(got.Ranges))
	}
	ranged := got.Ranges[0]
	if s, err := ranged.Check("2.0", ranged.Range); s != version.NotAffected || err != nil {
		t.Errorf("ranged bound Check(2.0) = %v, %v; want not affected", s, err)
	}
	if s, err := ranged.Check("2.0rc1", ranged.Range); s != version.CannotEvaluate || !errors.Is(err, version.ErrInvalidVersion) {
		t.Errorf("ranged bound Check(2.0rc1) = %v, %v; want cannot evaluate, invalid version (numeric order)", s, err)
	}
	for i, b := range got.Ranges[1:] {
		for _, candidate := range []string{"0", "1.0", "2.0", "99.0"} {
			if s, _ := b.Check(candidate, b.Range); s != version.CannotEvaluate {
				t.Errorf("unbounded row %d Check(%s) = %v, want cannot evaluate", i+1, candidate, s)
			}
		}
	}
}

// cpeAffectedRows returns n rows that each contain 1.0.
func cpeAffectedRows(n int) []CPERow {
	rows := make([]CPERow, n)
	for i := range rows {
		rows[i] = cpeRow(cpeNodeAny, cpeBounds{endExcluding: "2.0"})
	}
	return rows
}

// TestEvaluateCPERowsMeter checks one tick per row, including rows that cannot
// be compared, and that evaluation stops with the zero Outcome once Tick refuses.
func TestEvaluateCPERowsMeter(t *testing.T) {
	t.Parallel()

	t.Run("one tick per row", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }
		rows := append(cpeAffectedRows(2), cpeRow(cpeNodeNA, cpeBounds{}), cpeRow("cpe:2.3:a", cpeBounds{}))
		got := EvaluateCPERows(m, "1.0", rows, 0)
		if ticks != 4 {
			t.Errorf("ticks = %d, want 4", ticks)
		}
		if got.Verdict != Affected {
			t.Errorf("verdict = %v, want Affected", got.Verdict)
		}
	})

	t.Run("cancelled context stops at the 1,000th row with the zero outcome", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		ticks := 0
		m.onTick = func() { ticks++ }
		got := EvaluateCPERows(m, "1.0", cpeAffectedRows(2500), 0)
		if ticks != 1000 {
			t.Errorf("ticks = %d, want 1000", ticks)
		}
		if !reflect.DeepEqual(got, Outcome{}) {
			t.Errorf("outcome after Tick refused = %+v, want the zero Outcome", got)
		}
		if !errors.Is(m.Err(), context.Canceled) {
			t.Errorf("Err() = %v, want context.Canceled", m.Err())
		}
	})
}
