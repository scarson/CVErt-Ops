// ABOUTME: Tests how one advisory's primary rows and CNA entries combine into one verdict (design section 4.4).
// ABOUTME: Covers every worked example, each of the five steps alone, their precedence, and that CNA data alone never clears.
package check

import (
	"reflect"
	"testing"

	"github.com/scarson/cvert-ops/internal/version"
)

const (
	cpeNginx1270 = "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*"
	cpeOtherAny  = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
)

// numericBound is a primary range read in numeric order, as an NVD row is.
func numericBound(r version.Range) Bound {
	return Bound{Range: r, Check: version.CheckNumeric}
}

// Primary outcomes, as EvaluateCPERows or EvaluatePackageRows return them.
var (
	// No rows: rowVerdicts with nothing recorded.
	primaryNoRows = Outcome{}

	primaryAffected = Outcome{
		Verdict:    Affected,
		Matched:    []Matched{matchedCPE(cpeOtherAny, "1.0", "2.0", "")},
		Candidates: []string{"2.0"},
		Ranges:     []Bound{numericBound(version.Range{Introduced: "1.0", Fixed: "2.0"})},
		Comparable: true,
	}
	primaryNotAffected = Outcome{
		Verdict:    NotAffected,
		Ranges:     []Bound{numericBound(version.Range{Introduced: "1.0", Fixed: "2.0"})},
		Comparable: true,
	}
	primaryCannotEvaluate = Outcome{
		Verdict: CannotEvaluate,
		Reason:  ReasonNoVersionBounds,
		Ranges:  []Bound{numericBound(version.Range{})},
	}
)

var (
	cnaAffected = CNAResult{
		Reading: AffectedReading, Candidates: []string{"1.5"}, Matched: cnaMatched("1.0", "1.5", ""),
	}
	cnaIndeterminate = CNAResult{Reading: Indeterminate}
	cnaNoVersionInfo = CNAResult{Reading: NoVersionInfo}
	cnaNoStatement   = CNAResult{Reading: NoStatement}
)

// combined is the comparable part of an Outcome: everything but the Check
// functions in Ranges, which reflect cannot compare.
type combined struct {
	Verdict    Verdict
	Reason     Reason
	Matched    []Matched
	Candidates []string
	Ranges     []version.Range
	Comparable bool
}

func combinedOf(o Outcome) combined {
	return combined{
		Verdict: o.Verdict, Reason: o.Reason, Matched: o.Matched, Candidates: o.Candidates,
		Ranges: boundRanges(o.Ranges), Comparable: o.Comparable,
	}
}

func TestCombineWorkedExamples(t *testing.T) {
	t.Parallel()
	node24 := version.Range{Introduced: "23.0.0", Fixed: "24.22.1"}
	node26 := version.Range{Introduced: "26.0.0", LastAffected: "26.5.0"}
	nginx := version.Range{Introduced: "1.27.0", LastAffected: "1.27.0"}

	tests := []struct {
		name           string
		primary        Outcome
		hasPrimaryRows bool
		cna            CNAResult
		want           combined
	}{
		{
			// The CNA record names Google Brotli, so no CNA row is found for Node.
			name: "Node 24.22.0, CVE-2026-111497: NVD range contains it",
			primary: Outcome{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNodeAny, "23.0.0", "24.22.1", "")},
				Candidates: []string{"24.22.1"}, Ranges: []Bound{numericBound(node24)}, Comparable: true,
			},
			hasPrimaryRows: true,
			cna:            cnaNoStatement,
			want: combined{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNodeAny, "23.0.0", "24.22.1", "")},
				Candidates: []string{"24.22.1"}, Ranges: []version.Range{node24}, Comparable: true,
			},
		},
		{
			name:           "Node 24.22.1, CVE-2026-111497: outside every NVD range, no CNA rows",
			primary:        Outcome{Verdict: NotAffected, Ranges: []Bound{numericBound(node24)}, Comparable: true},
			hasPrimaryRows: true,
			cna:            cnaNoStatement,
			want:           combined{Verdict: NotAffected, Ranges: []version.Range{node24}, Comparable: true},
		},
		{
			// CNA: {1.25.0, lt 1.27.1, affected}, unaffected at 1.26.2 and
			// 1.27.1, so 1.27.0 is above the first change: Indeterminate. The
			// NVD row is a literal-version row, one shape that marks it vulnerable.
			name: "nginx 1.27.0, CVE-2024-7347: NVD marks it vulnerable, CNA Indeterminate",
			primary: Outcome{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNginx1270, "1.27.0", "", "1.27.0")},
				Ranges: []Bound{numericBound(nginx)}, Comparable: true,
			},
			hasPrimaryRows: true,
			cna:            cnaIndeterminate,
			want: combined{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNginx1270, "1.27.0", "", "1.27.0")},
				Ranges: []version.Range{nginx}, Comparable: true,
			},
		},
		{
			name:           "Log4j 2.14.0, CVE-2021-44228: CNA row alone, inside the segment stepping to affected at 2.13.0",
			primary:        primaryNoRows,
			hasPrimaryRows: false,
			cna: CNAResult{
				Reading: AffectedReading, Candidates: []string{"2.15.0"}, Matched: cnaMatched("2.13.0", "2.15.0", ""),
			},
			want: combined{
				Verdict: Affected, Matched: cnaMatched("2.13.0", "2.15.0", ""), Candidates: []string{"2.15.0"},
			},
		},
		{
			name:           "Node 12.22.12, CVE-2024-27980: outside every NVD range, CNA 12.0 to 12.* Indeterminate",
			primary:        Outcome{Verdict: NotAffected, Ranges: []Bound{numericBound(version.Range{Introduced: "14.0.0", Fixed: "14.21.3"})}, Comparable: true},
			hasPrimaryRows: true,
			cna:            cnaIndeterminate,
			want: combined{
				Verdict: CannotEvaluate, Reason: ReasonCNAIndeterminate,
				Ranges: []version.Range{{Introduced: "14.0.0", Fixed: "14.21.3"}}, Comparable: true,
			},
		},
		{
			name: "Node 26.4.0, CVE-2026-56847: NVD [26.0.0, 26.5.0] contains it, CNA no statement",
			primary: Outcome{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNodeAny, "26.0.0", "", "26.5.0")},
				Ranges: []Bound{numericBound(node26)}, Comparable: true,
			},
			hasPrimaryRows: true,
			cna:            cnaNoStatement,
			want: combined{
				Verdict: Affected, Matched: []Matched{matchedCPE(cpeNodeAny, "26.0.0", "", "26.5.0")},
				Ranges: []version.Range{node26}, Comparable: true,
			},
		},
		{
			name:           "Node 26.4.0, CVE-2026-56847 before NVD analyses it: CNA no statement",
			primary:        primaryNoRows,
			hasPrimaryRows: false,
			cna:            cnaNoStatement,
			want:           combined{Verdict: CannotEvaluate, Reason: ReasonCNACannotClear},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := combinedOf(Combine(tt.primary, tt.hasPrimaryRows, tt.cna))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Combine:\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}

func TestCombineSteps(t *testing.T) {
	t.Parallel()
	primaryRange := []version.Range{{Introduced: "1.0", Fixed: "2.0"}}
	tests := []struct {
		name           string
		primary        Outcome
		hasPrimaryRows bool
		cna            CNAResult
		want           combined
	}{
		// Step 1: Affected if a primary row or a CNA entry reports Affected.
		{
			name: "step 1: primary Affected alone", primary: primaryAffected, hasPrimaryRows: true, cna: cnaNoStatement,
			want: combined{
				Verdict: Affected, Matched: primaryAffected.Matched, Candidates: []string{"2.0"},
				Ranges: primaryRange, Comparable: true,
			},
		},
		{
			name: "step 1: CNA Affected alone, primary rows Not affected", primary: primaryNotAffected, hasPrimaryRows: true, cna: cnaAffected,
			want: combined{
				Verdict: Affected, Matched: cnaAffected.Matched, Candidates: []string{"1.5"},
				Ranges: primaryRange, Comparable: true,
			},
		},
		{
			name: "step 1: both Affected, primary's matches and candidates first", primary: primaryAffected, hasPrimaryRows: true, cna: cnaAffected,
			want: combined{
				Verdict:    Affected,
				Matched:    append(append([]Matched{}, primaryAffected.Matched...), cnaAffected.Matched...),
				Candidates: []string{"2.0", "1.5"}, Ranges: primaryRange, Comparable: true,
			},
		},
		{
			name: "step 1 before step 2: CNA Affected, primary CannotEvaluate", primary: primaryCannotEvaluate, hasPrimaryRows: true, cna: cnaAffected,
			want: combined{
				Verdict: Affected, Matched: cnaAffected.Matched, Candidates: []string{"1.5"},
				Ranges: []version.Range{{}},
			},
		},
		{
			name: "step 1 before step 3: primary Affected, CNA Indeterminate", primary: primaryAffected, hasPrimaryRows: true, cna: cnaIndeterminate,
			want: combined{
				Verdict: Affected, Matched: primaryAffected.Matched, Candidates: []string{"2.0"},
				Ranges: primaryRange, Comparable: true,
			},
		},

		// Step 2: CannotEvaluate, with the primary's reason, if a primary row cannot be compared.
		{
			name: "step 2: primary CannotEvaluate, CNA no statement", primary: primaryCannotEvaluate, hasPrimaryRows: true, cna: cnaNoStatement,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds, Ranges: []version.Range{{}}},
		},
		{
			name: "step 2 before step 3: primary CannotEvaluate, CNA Indeterminate", primary: primaryCannotEvaluate, hasPrimaryRows: true, cna: cnaIndeterminate,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonNoVersionBounds, Ranges: []version.Range{{}}},
		},

		// Step 3: CannotEvaluate, cna_indeterminate, if a CNA entry is Indeterminate.
		{
			name: "step 3 before step 4: primary Not affected, CNA Indeterminate", primary: primaryNotAffected, hasPrimaryRows: true, cna: cnaIndeterminate,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonCNAIndeterminate, Ranges: primaryRange, Comparable: true},
		},
		{
			name: "step 3: no primary rows, CNA Indeterminate", primary: primaryNoRows, hasPrimaryRows: false, cna: cnaIndeterminate,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonCNAIndeterminate},
		},

		// Step 4: Not affected if the primary rows are comparable and all report Not affected.
		{
			name: "step 4: primary Not affected, CNA no statement", primary: primaryNotAffected, hasPrimaryRows: true, cna: cnaNoStatement,
			want: combined{Verdict: NotAffected, Ranges: primaryRange, Comparable: true},
		},
		{
			name: "step 4: an entry with no version information does not stop it", primary: primaryNotAffected, hasPrimaryRows: true, cna: cnaNoVersionInfo,
			want: combined{Verdict: NotAffected, Ranges: primaryRange, Comparable: true},
		},
		{
			// rowVerdicts never builds this outcome; a Not affected verdict that
			// compared no row is not evidence, so it must not clear the version.
			name:           "step 4 needs a comparable row",
			primary:        Outcome{Verdict: NotAffected, Ranges: []Bound{numericBound(version.Range{Introduced: "1.0", Fixed: "2.0"})}},
			hasPrimaryRows: true, cna: cnaNoStatement,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonCNACannotClear, Ranges: primaryRange},
		},

		// Step 5: with no primary rows, CNA Affected stands and anything else cannot clear.
		{
			name: "step 5: no primary rows, CNA no version information", primary: primaryNoRows, hasPrimaryRows: false, cna: cnaNoVersionInfo,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonCNACannotClear},
		},
		{
			// hasPrimaryRows is the caller's statement; a Not affected outcome
			// without rows behind it does not reach step 4.
			name: "step 5: Not affected outcome without primary rows", primary: primaryNotAffected, hasPrimaryRows: false, cna: cnaNoStatement,
			want: combined{Verdict: CannotEvaluate, Reason: ReasonCNACannotClear, Ranges: primaryRange, Comparable: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := combinedOf(Combine(tt.primary, tt.hasPrimaryRows, tt.cna))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Combine:\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}

// A CNA-only advisory answers Affected or CannotEvaluate, never NotAffected
// (design section 4.3), whatever the CNA reading.
func TestCombineCNAOnlyNeverClears(t *testing.T) {
	t.Parallel()
	want := map[Reading]combined{
		NoStatement:     {Verdict: CannotEvaluate, Reason: ReasonCNACannotClear},
		NoVersionInfo:   {Verdict: CannotEvaluate, Reason: ReasonCNACannotClear},
		Indeterminate:   {Verdict: CannotEvaluate, Reason: ReasonCNAIndeterminate},
		AffectedReading: {Verdict: Affected, Matched: cnaAffected.Matched, Candidates: []string{"1.5"}},
	}
	for _, reading := range []Reading{NoStatement, NoVersionInfo, Indeterminate, AffectedReading} {
		cna := CNAResult{Reading: reading}
		if reading == AffectedReading {
			cna = cnaAffected
		}
		got := combinedOf(Combine(primaryNoRows, false, cna))
		if got.Verdict == NotAffected {
			t.Errorf("reading %d: CNA data alone cleared the version", reading)
		}
		if !reflect.DeepEqual(got, want[reading]) {
			t.Errorf("reading %d:\n got  %+v\n want %+v", reading, got, want[reading])
		}
	}
}

// The combined outcome's Matched and Candidates must not share storage with
// the primary outcome's, so appending to one never changes the other.
func TestCombineDoesNotAliasPrimarySlices(t *testing.T) {
	t.Parallel()
	primary := primaryAffected
	primary.Matched = make([]Matched, 1, 4)
	primary.Matched[0] = primaryAffected.Matched[0]
	primary.Candidates = make([]string, 1, 4)
	primary.Candidates[0] = "2.0"

	got := Combine(primary, true, cnaAffected)
	got.Matched[0].Introduced = "changed"
	got.Candidates[0] = "changed"
	if primary.Matched[0].Introduced != "1.0" || primary.Candidates[0] != "2.0" {
		t.Errorf("Combine shares storage with the primary outcome: %+v %v", primary.Matched, primary.Candidates)
	}
}
