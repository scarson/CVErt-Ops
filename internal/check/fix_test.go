// ABOUTME: Tests fix reporting: the lowest candidate no range or CNA entry still reports, and fix_major.
// ABOUTME: Covers design section 7's four steps, unreadable candidates, duplicates and the work meter.
package check

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/version"
)

// fixResult is PickFix's answer, with fix_major dereferenced; hasMajor is false
// when fix_major is nil.
type fixResult struct {
	fixed, major string
	hasMajor     bool
}

func pickFix(t *testing.T, ver string, candidates []string, order version.Order, ranges []Bound,
	cna func(string) Reading) fixResult {
	t.Helper()
	m := newWorkMeter(context.Background())
	fixed, major := PickFix(m, ver, candidates, order, ranges, cna)
	if err := m.Err(); err != nil {
		t.Fatalf("meter error after picking a fix: %v", err)
	}
	if (fixed == "") != (major == nil) {
		t.Fatalf("PickFix = %q with fix_major %v: fix_major must be set exactly when a fix is", fixed, major)
	}
	if major == nil {
		return fixResult{fixed: fixed}
	}
	return fixResult{fixed: fixed, major: *major, hasMajor: true}
}

func wantFix(fix, major string) fixResult { return fixResult{fixed: fix, major: major, hasMajor: true} }

// npmBound is a range read the way an npm package row is.
func npmBound(introduced, fix string) Bound {
	return Bound{
		Range: version.Range{Introduced: introduced, Fixed: fix},
		Check: func(v string, r version.Range) (version.Status, error) { return version.Check("npm", v, r) },
	}
}

// stubBound answers status for the versions listed and NotAffected for any other.
func stubBound(status version.Status, versions ...string) Bound {
	return Bound{Check: func(v string, _ version.Range) (version.Status, error) {
		for _, listed := range versions {
			if v == listed {
				return status, nil
			}
		}
		return version.NotAffected, nil
	}}
}

// cnaReads returns a cna func reading r for the candidates listed and NoStatement otherwise.
func cnaReads(r Reading, candidates ...string) func(string) Reading {
	return func(c string) Reading {
		for _, listed := range candidates {
			if c == listed {
				return r
			}
		}
		return NoStatement
	}
}

// nodeRows returns Node's maintained lines, one range per line, as an advisory
// with no lower bound on its oldest line stores them. Each call returns fresh
// rows, because evaluate sets their ecosystem.
func nodeRows() []PackageRow {
	return []PackageRow{
		pkgRow("ECOSYSTEM", "23.0.0", "24.22.1", ""),
		pkgRow("ECOSYSTEM", "0", "22.23.4", ""),
	}
}

// TestPickFixFromPackageRows reads candidates and ranges from EvaluatePackageRows,
// as the endpoint does for a package item.
func TestPickFixFromPackageRows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version string
		rows    []PackageRow
		want    fixResult
	}{
		// Design 7: only ranges containing the version give candidates, so 22.23.4 is never considered.
		{"Node 24.22.0 takes the fix on its own line", "24.22.0", nodeRows(), wantFix("24.22.1", "same")},
		// Design 7, "Same branch": a range with no lower bound gives a fix on another line.
		{"Node 20.0.0 below every line", "20.0.0", nodeRows(), wantFix("22.23.4", "different")},
		// Design 7, "Same branch": a range with a lower bound can cross lines too.
		{"Node 23.1.0 crosses into 24", "23.1.0", nodeRows(), wantFix("24.22.1", "different")},
		// A row with no introduced bound cannot be compared, so it cannot clear the candidate.
		{
			"a row that cannot be compared blocks the fix", "1.0.0",
			[]PackageRow{pkgRow("ECOSYSTEM", "0", "1.2.0", ""), pkgRow("ECOSYSTEM", "", "1.3.0", "")},
			fixResult{},
		},
		// A last_affected bound is not a candidate (design 7, step 1).
		{"last_affected gives no fix", "1.0.0", []PackageRow{pkgRow("ECOSYSTEM", "0", "", "1.2.0")}, fixResult{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := evaluate(t, "npm", tc.version, tc.rows)
			got := pickFix(t, tc.version, out.Candidates, version.EcosystemOrder("npm"), out.Ranges, nil)
			if got != tc.want {
				t.Errorf("PickFix = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPickFixSemverRowsInDebian checks that a SEMVER row in Debian rejects a
// candidate either order still reports. 2.0.0 is outside [1.9.9, 2.0.0-1) under
// SemVer, where 2.0.0-1 is a prerelease below 2.0.0, and inside it under dpkg.
func TestPickFixSemverRowsInDebian(t *testing.T) {
	t.Parallel()
	out := evaluate(t, "Debian:13", "1.0.0", []PackageRow{
		pkgRow("SEMVER", "0", "2.0.0", ""),
		pkgRow("SEMVER", "1.9.9", "2.0.0-1", ""),
	})
	if out.Verdict != Affected || !reflect.DeepEqual(out.Candidates, []string{"2.0.0"}) {
		t.Fatalf("verdict %v, candidates %v; want Affected with candidate 2.0.0", out.Verdict, out.Candidates)
	}
	got := pickFix(t, "1.0.0", out.Candidates, version.EcosystemOrder("Debian:13"), out.Ranges, nil)
	if got != (fixResult{}) {
		t.Errorf("PickFix = %+v, want no fix", got)
	}
}

// TestPickFixFromCPERows reads candidates and ranges from EvaluateCPERows, as
// the endpoint does for a CPE item, with the order CheckNumeric uses.
func TestPickFixFromCPERows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		rows []CPERow
		want fixResult
	}{
		// Design 7: two sources disagree; 1.2.3 is still inside the second range.
		{
			"two sources take the higher fix",
			[]CPERow{
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.2.3"}),
				cpeRow(cpeNodeAny, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.2.4"}),
			},
			wantFix("1.2.4", "same"),
		},
		// A row with no version bounds answers cannot evaluate for every candidate.
		{
			"a row with no bounds blocks the fix",
			[]CPERow{cpeRow(cpeNodeAny, cpeBounds{endExcluding: "1.2.3"}), cpeRow(cpeNodeAny, cpeBounds{})},
			fixResult{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := evaluateCPE(t, "1.2.0", tc.rows)
			got := pickFix(t, "1.2.0", out.Candidates, version.NumericOrder, out.Ranges, nil)
			if got != tc.want {
				t.Errorf("PickFix = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPickFixCNA checks design 7, step 3: a candidate a CNA entry reports as
// Affected or Indeterminate is rejected, and the next candidate is taken.
func TestPickFixCNA(t *testing.T) {
	t.Parallel()
	ranges := []Bound{npmBound("1.0.0", "1.2.3"), npmBound("1.0.0", "1.2.4")}
	candidates := []string{"1.2.3", "1.2.4"}
	tests := []struct {
		name string
		cna  func(string) Reading
		want fixResult
	}{
		{"no CNA entries", nil, wantFix("1.2.4", "same")},
		{"Indeterminate rejects", cnaReads(Indeterminate, "1.2.4"), fixResult{}},
		{"Affected rejects", cnaReads(AffectedReading, "1.2.4"), fixResult{}},
		{"no version information does not reject", cnaReads(NoVersionInfo, "1.2.4"), wantFix("1.2.4", "same")},
		{"no statement does not reject", cnaReads(NoStatement, "1.2.4"), wantFix("1.2.4", "same")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickFix(t, "1.2.0", candidates, version.EcosystemOrder("npm"), ranges, tc.cna)
			if got != tc.want {
				t.Errorf("PickFix = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("Indeterminate rejects and the next candidate is taken", func(t *testing.T) {
		t.Parallel()
		got := pickFix(t, "1.2.0", []string{"1.2.3", "1.3.0"}, version.EcosystemOrder("npm"),
			[]Bound{npmBound("1.0.0", "1.2.3")}, cnaReads(Indeterminate, "1.2.3"))
		if want := wantFix("1.3.0", "same"); got != want {
			t.Errorf("PickFix = %+v, want %+v", got, want)
		}
	})

	// The wiring the endpoint uses: the cna func re-reads the advisory's CNA rows
	// at the candidate. The entry still reports 1.2.3 as affected.
	t.Run("ReadCNAEntries rejects a candidate inside its segment", func(t *testing.T) {
		t.Parallel()
		rows := oneEntry(CNAVersion{Version: "1.0.0", LessThan: "1.2.4", Status: "affected", VersionType: "semver"})
		m := newWorkMeter(context.Background())
		cna := func(c string) Reading { return ReadCNAEntries(m, c, rows).Reading }
		got := pickFix(t, "1.2.0", []string{"1.2.3", "1.2.4"}, version.EcosystemOrder("npm"),
			[]Bound{npmBound("1.0.0", "1.2.3")}, cna)
		if want := wantFix("1.2.4", "same"); got != want {
			t.Errorf("PickFix = %+v, want %+v", got, want)
		}
	})
}

// TestPickFixRanges checks that every range must answer NotAffected for a candidate.
func TestPickFixRanges(t *testing.T) {
	t.Parallel()
	order := version.EcosystemOrder("npm")
	tests := []struct {
		name       string
		candidates []string
		ranges     []Bound
		want       fixResult
	}{
		{
			"cannot evaluate from another range rejects", []string{"1.2.3", "1.4.0"},
			[]Bound{npmBound("1.0.0", "1.2.3"), stubBound(version.CannotEvaluate, "1.2.3")},
			wantFix("1.4.0", "same"),
		},
		{
			"affected from another range rejects", []string{"1.2.3"},
			[]Bound{npmBound("1.0.0", "1.2.3"), stubBound(version.Affected, "1.2.3")},
			fixResult{},
		},
		{
			"lowest passing candidate in any input order", []string{"2.0.0", "1.5.0", "1.8.0"},
			[]Bound{npmBound("1.0.0", "1.5.0")},
			wantFix("1.5.0", "same"),
		},
		{"no ranges leaves the lowest candidate", []string{"3.0.0", "2.0.0"}, nil, wantFix("2.0.0", "different")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickFix(t, "1.2.0", tc.candidates, order, tc.ranges, nil)
			if got != tc.want {
				t.Errorf("PickFix = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestPickFixNoMinimum checks design 7, step 2, and the inputs that give no fix at all.
func TestPickFixNoMinimum(t *testing.T) {
	t.Parallel()
	// A range answering NotAffected for every candidate, so only the order or
	// the inputs can withhold the fix.
	ranges := []Bound{stubBound(version.Affected)}
	tests := []struct {
		name       string
		candidates []string
		order      version.Order
	}{
		{"a candidate the order cannot read beside numeric ones", []string{"1.2", "1.1rc1"}, version.NumericOrder},
		{"a lone candidate the order cannot read", []string{"1.1rc1"}, version.NumericOrder},
		{"no order for the ecosystem", []string{"1.2"}, nil},
		{"no candidates", nil, version.NumericOrder},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := pickFix(t, "1.0", tc.candidates, tc.order, ranges, nil); got != (fixResult{}) {
				t.Errorf("PickFix = %+v, want no fix", got)
			}
		})
	}
}

// TestPickFixMajor checks fix_major in PickFix's answer for versions read by
// each kind of order.
func TestPickFixMajor(t *testing.T) {
	t.Parallel()
	debianCheck := func(v string, r version.Range) (version.Status, error) { return version.Check("Debian:13", v, r) }
	goCheck := func(v string, r version.Range) (version.Status, error) { return version.Check("Go", v, r) }
	tests := []struct {
		name, version, candidate string
		order                    version.Order
		ranges                   []Bound
		want                     fixResult
	}{
		{
			"epochs are skipped", "1:2.0", "1:2.1", version.EcosystemOrder("Debian:13"),
			[]Bound{{Range: version.Range{Introduced: "1:1.0", Fixed: "1:2.1"}, Check: debianCheck}},
			wantFix("1:2.1", "same"),
		},
		{
			"Go module versions start with v", "v1.2.3", "v1.3.0", version.EcosystemOrder("Go"),
			[]Bound{{Range: version.Range{Introduced: "0", Fixed: "v1.3.0"}, Check: goCheck}},
			wantFix("v1.3.0", "same"),
		},
		{
			"a version with no leading number", "dev-main", "2.0", version.NumericOrder,
			[]Bound{numericBound(version.Range{Introduced: "0", Fixed: "1.0"})},
			wantFix("2.0", "unknown"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pickFix(t, tc.version, []string{tc.candidate}, tc.order, tc.ranges, nil)
			if got != tc.want {
				t.Errorf("PickFix = %+v, want %+v", got, tc.want)
			}
		})
	}

	t.Run("each answer has its own fix_major", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		_, first := PickFix(m, "1.0", []string{"1.1"}, version.NumericOrder, nil, nil)
		*first = "different"
		_, second := PickFix(m, "1.0", []string{"1.1"}, version.NumericOrder, nil, nil)
		if *second != "same" {
			t.Errorf("fix_major after changing an earlier answer = %q, want same", *second)
		}
	})
}

func TestFixMajor(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("9", 60)
	tests := []struct{ version, fix, want string }{
		{"24.22.0", "24.22.1", "same"},
		{"20.0.0", "22.23.4", "different"},
		{"1:2.0", "1:2.1", "same"},
		{"2.0", "1:2.1", "same"},
		{"1:2.0", "1:3.0", "different"},
		{"1!2.0", "1!3.0", "different"}, // PEP 440 epoch
		{"v1.2.3", "v1.3.0", "same"},
		{"V1.2.3", "1.3.0", "same"},
		{"v1.2.3", "v2.0.0", "different"},
		{"01.2", "1.3", "same"},
		{"0.9", "00.10", "same"},
		{long + ".1", "000" + long + ".2", "same"},
		{long + ".1", long + "8.2", "different"},
		{"dev-main", "2.0", "unknown"},
		{"1.0", "latest", "unknown"},
		{"1:abc", "1.0", "unknown"}, // no number after the epoch
		{"v", "1.0", "unknown"},
		{"vx1", "1.0", "unknown"},
		{"", "1.0", "unknown"},
	}
	for _, tc := range tests {
		if got := fixMajorOf(tc.version, tc.fix); got != tc.want {
			t.Errorf("fixMajorOf(%q, %q) = %q, want %q", tc.version, tc.fix, got, tc.want)
		}
	}
}

// TestPickFixWork checks that candidates are walked lowest first, each checked
// once, and that the walk stops at the first one that passes.
func TestPickFixWork(t *testing.T) {
	t.Parallel()

	t.Run("stops at the first passing candidate", func(t *testing.T) {
		t.Parallel()
		var checked, readByCNA []string
		recording := Bound{Check: func(v string, _ version.Range) (version.Status, error) {
			checked = append(checked, v)
			if v == "1.0" {
				return version.Affected, nil
			}
			return version.NotAffected, nil
		}}
		cna := func(c string) Reading {
			readByCNA = append(readByCNA, c)
			return NoStatement
		}
		orderCalls := 0
		counting := func(a, b string) (int, error) {
			orderCalls++
			return version.NumericOrder(a, b)
		}
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }

		got, major := PickFix(m, "0.5", []string{"4.0", "2.0", "1.0", "3.0"}, counting, []Bound{recording, recording}, cna)
		if got != "2.0" || major == nil || *major != "different" {
			t.Errorf("PickFix = %q, %v; want 2.0, different", got, major)
		}
		// 1.0 is rejected by the first range; 2.0 passes both ranges and the CNA entries.
		if want := []string{"1.0", "2.0", "2.0"}; !reflect.DeepEqual(checked, want) {
			t.Errorf("ranges checked %v, want %v", checked, want)
		}
		if want := []string{"2.0"}; !reflect.DeepEqual(readByCNA, want) {
			t.Errorf("CNA entries read at %v, want %v", readByCNA, want)
		}
		if ticks != 4 {
			t.Errorf("ticks = %d, want 4 (one per range check and CNA read)", ticks)
		}
		if orderCalls == 0 {
			t.Error("order was never called; candidates must be sorted by it")
		}
	})

	t.Run("duplicate candidates are checked once", func(t *testing.T) {
		t.Parallel()
		var checked []string
		recording := Bound{Check: func(v string, _ version.Range) (version.Status, error) {
			checked = append(checked, v)
			return version.Affected, nil
		}}
		m := newWorkMeter(context.Background())
		got, _ := PickFix(m, "1.0", []string{"1.2", "1.2.0", "1.2", "1.3"}, version.NumericOrder, []Bound{recording}, nil)
		if got != "" {
			t.Errorf("PickFix = %q, want no fix", got)
		}
		if len(checked) != 2 || checked[1] != "1.3" {
			t.Errorf("ranges checked %v, want one spelling of 1.2, then 1.3", checked)
		}
	})

	t.Run("a refused tick stops with no fix", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(cancelledContext())
		_ = m.Err() // the meter refuses every later tick
		checked := 0
		counting := Bound{Check: func(string, version.Range) (version.Status, error) {
			checked++
			return version.NotAffected, nil
		}}
		got, major := PickFix(m, "1.0", []string{"1.1"}, version.NumericOrder, []Bound{counting}, nil)
		if got != "" || major != nil {
			t.Errorf("PickFix = %q, %v; want no fix", got, major)
		}
		if checked != 0 {
			t.Errorf("ranges checked %d times after the meter refused, want 0", checked)
		}
	})

	t.Run("a refused tick before the CNA read stops with no fix", func(t *testing.T) {
		t.Parallel()
		m := newWorkMeter(context.Background())
		cna := func(string) Reading {
			t.Error("CNA entries read after the meter refused")
			return NoStatement
		}
		stopping := Bound{Check: func(string, version.Range) (version.Status, error) {
			m.err = context.Canceled
			return version.NotAffected, nil
		}}
		got, major := PickFix(m, "1.0", []string{"1.1"}, version.NumericOrder, []Bound{stopping}, cna)
		if got != "" || major != nil {
			t.Errorf("PickFix = %q, %v; want no fix", got, major)
		}
	})
}
