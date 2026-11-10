// ABOUTME: Tests the rows a CPE lookup leaves out as lying wholly below the lowest version asked of a product, and the rows standing for them.
// ABOUTME: Pins that leaving them out changes no answer: verdicts, reasons, counts and fixes equal the unfiltered read's.
package check

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/version"
)

const widgetPrefix = "cpe:2.3:a:acme:widget:"

// widgetExact is a row naming one version of acme:widget; widgetRange is a row
// with the wildcard version component and the given bounds.
func widgetExact(cve, component string) CPERow {
	return CPERow{CVEID: cve, CPE: widgetPrefix + component + ":*:*:*:*:*:*:*"}
}

func widgetRange(cve string, b cpeBounds) CPERow {
	row := cpeRow(widgetCPE, b)
	row.CVEID = cve
	return row
}

func TestCPERowBelow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ver  string
		row  CPERow
		want bool
	}{
		{"exact release below", "6.12.0", widgetExact(cveA, "2.6.32"), true},
		{"exact suffixed release below", "6.12.0", widgetExact(cveA, "2.6.22_rc7"), true},
		{"exact release with an update component", "6.12.0", CPERow{CPE: widgetPrefix + "2.6.32:rc1:*:*:*:*:*:*"}, true},
		{"exact release with an escape in a later component", "6.12.0", CPERow{CPE: widgetPrefix + `2.6.32:*:*:*:*:joomla\!:*:*`}, true},
		{"exact release equal", "6.12.0", widgetExact(cveA, "6.12.0"), false},
		{"exact release above", "6.12.0", widgetExact(cveA, "6.13"), false},
		{"exact release with an escaped character", "6.12.0", widgetExact(cveA, `1.2\(55\)se`), false},
		{"exact release with an escaped epoch", "6.12.0", widgetExact(cveA, `1\:2.0`), false},
		{"range ending below, exclusive", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "5.15", endExcluding: "5.15.100"}), true},
		{"range ending below, inclusive", "6.12.0", widgetRange(cveA, cpeBounds{startExcluding: "5.15", endIncluding: "5.15.100"}), true},
		{"range with no start, ending below", "6.12.0", widgetRange(cveA, cpeBounds{endExcluding: "2.6.9"}), true},
		{"range containing the version", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "6.1", endExcluding: "6.13"}), false},
		{"range above the version", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "6.13", endExcluding: "6.14"}), false},
		{"range with no end", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "2.6"}), false},
		{"inverted range", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "3.0", endExcluding: "2.0"}), false},
		{"both start bounds", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "1.0", startExcluding: "1.0", endExcluding: "2.0"}), false},
		{"both end bounds", "6.12.0", widgetRange(cveA, cpeBounds{startIncluding: "1.0", endIncluding: "2.0", endExcluding: "2.0"}), false},
		{"no bounds", "6.12.0", widgetRange(cveA, cpeBounds{}), false},
		{"version component -", "6.12.0", widgetExact(cveA, "-"), false},
		{"literal version component with bounds", "6.12.0", CPERow{CPE: widgetPrefix + "2.0:*:*:*:*:*:*:*", VersionEndExcluding: "3.0"}, false},
		{"twelve components", "6.12.0", CPERow{CPE: widgetPrefix + "2.0:*:*:*:*:*:*"}, false},
		{"escaped colon makes twelve components", "6.12.0", CPERow{CPE: widgetPrefix + `2.0\:*:*:*:*:*:*:*`}, false},
		{"version that is not dotted numbers", "6.12.0-rc1", widgetExact(cveA, "2.6.32"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := CPERowBelow(tc.ver, tc.row); got != tc.want {
				t.Errorf("CPERowBelow(%q, %+v) = %v, want %v", tc.ver, tc.row, got, tc.want)
			}
		})
	}
}

// TestKeysForCPEFloor checks that a product has one key whatever the number of
// versions asked of it, that the key's floor is the lowest of those versions
// when all are dotted numbers, that one version that is not dotted numbers
// leaves the key with no floor wherever it comes in the request, and that a
// vendor range carries no floor.
func TestKeysForCPEFloor(t *testing.T) {
	t.Parallel()
	const gadgetCPE = "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*"
	tests := []struct {
		name     string
		versions []string
		want     string
	}{
		{"one version", []string{"6.12.0"}, "6.12.0"},
		{"the lowest of several", []string{"6.12.0", "6.13", "5.15.100", "7", "5.15.100.1"}, "5.15.100"},
		{"lowest by value, not as text", []string{"10.0", "9.5"}, "9.5"},
		{"equal versions keep the first spelling", []string{"6.12", "6.12.0", "6.12.0.0"}, "6.12"},
		{"a version that is not dotted numbers, last", []string{"6.12.0", "5.15", "6.8.0-45-generic"}, ""},
		{"a version that is not dotted numbers, first", []string{"6.8.0-45-generic", "6.12.0", "5.15"}, ""},
		{"a version that is not dotted numbers, between", []string{"6.12.0", "6.8.0-45-generic", "5.15"}, ""},
		{"only versions that are not dotted numbers", []string{"6.8.0-45-generic", "1.24rc1"}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raws := []RawItem{{CPE: gadgetCPE, Version: "3.0"}}
			for _, v := range tc.versions {
				raws = append(raws, RawItem{CPE: widgetCPE, Version: v})
			}
			keys, uses := keysWithUses(parseItems(raws...))
			want := []CPEKey{
				{Lo: "cpe:2.3:a:acme:gadget:", Hi: "cpe:2.3:a:acme:gadget;", Floor: "3.0"},
				{Lo: widgetPrefix, Hi: "cpe:2.3:a:acme:widget;", Floor: tc.want},
			}
			if !reflect.DeepEqual(keys.CPEPrefixes, want) {
				t.Errorf("CPE keys =\n%+v\nwant\n%+v", keys.CPEPrefixes, want)
			}
			for i := range tc.versions {
				if got := uses[i+1].cpes; !reflect.DeepEqual(got, []int{1}) {
					t.Errorf("item %d CPE keys = %v, want [1]", i+1, got)
				}
			}
			for _, v := range tc.versions {
				if tc.want == "" {
					continue
				}
				if c, err := version.NumericOrder(tc.want, v); err != nil || c > 0 {
					t.Errorf("floor %q against version %q: order %d (%v), want at or below", tc.want, v, c, err)
				}
			}
			for _, near := range keys.CNANear {
				for _, r := range near.VendorRanges {
					if r.Floor != "" {
						t.Errorf("vendor range %+v carries a floor", r)
					}
				}
			}
		})
	}
}

// below is the row the store returns for n rows of cve left out as lying wholly
// below the key's floor.
func below(cve string, n int) CPERow { return CPERow{CVEID: cve, Below: n} }

// TestEvaluateRowsBelow checks what a row standing for left-out rows means: the
// CVE is NVD-analysed and those rows exclude the version.
func TestEvaluateRowsBelow(t *testing.T) {
	t.Parallel()
	items := parseItems(widgetItem)
	noStatement := CNAVersion{Version: "unspecified", Status: "affected"}
	affectedBelow2 := CNAVersion{Version: "0", LessThan: "2.0", Status: "affected", VersionType: "custom"}
	retracted := below(cveE, 3)
	retracted.Status = "Rejected"

	t.Run("counts as not affected, alone or beside rows that exclude the version", func(t *testing.T) {
		t.Parallel()
		r := rowsFor(t, items).cpes("acme", "widget",
			below(cveA, 40),
			below(cveB, 1), cpeAt(cveB, widgetCPE, "2.0", "3.0"),
			below(cveC, 2), cpeAt(cveC, widgetCPE, "1.0", "2.0"),
			below(cveD, 2), widgetRange(cveD, cpeBounds{}),
			retracted)
		got := run(t, items, r).Results[0]
		want := summary{status: StatusAffected, reason: "null", warnings: []string{},
			counts: Counts{Affected: 1, CannotEvaluate: 1, NotAffected: 2, Retracted: 1}, listed: []string{cveC, cveD}}
		if s := summarize(t, got); !reflect.DeepEqual(s, want) {
			t.Errorf("summary = %+v, want %+v", s, want)
		}
		if got.Advisories[0].FixedVersion == nil || *got.Advisories[0].FixedVersion != "2.0" {
			t.Errorf("fixed version of %s = %v, want 2.0", cveC, got.Advisories[0].FixedVersion)
		}
	})

	// Design section 4.4: with NVD rows that all exclude the version, a CNA entry
	// with no version information does not hold the advisory (step 4). Without
	// NVD rows the same entry is cna_cannot_clear (step 5).
	t.Run("is an NVD analysis beside a CNA entry with no version", func(t *testing.T) {
		t.Parallel()
		r := rowsFor(t, items).cpes("acme", "widget", below(cveA, 3)).
			cnaName("acme", "widget", false, cnaAt(cveA, "acme", "widget", noStatement), cnaAt(cveB, "acme", "widget", noStatement))
		got := run(t, items, r).Results[0]
		if want := (Counts{NotAffected: 1, CannotEvaluate: 1}); got.Counts != want {
			t.Errorf("counts = %+v, want %+v", got.Counts, want)
		}
		if want := map[string]string{cveB: "cannot_evaluate/cna_cannot_clear"}; !reflect.DeepEqual(advisoryReasons(got), want) {
			t.Errorf("advisories = %v, want %v", advisoryReasons(got), want)
		}
	})

	t.Run("does not clear a version a CNA entry reports", func(t *testing.T) {
		t.Parallel()
		r := rowsFor(t, items).cpes("acme", "widget", below(cveA, 3)).
			cnaName("acme", "widget", false, cnaAt(cveA, "acme", "widget", affectedBelow2))
		got := run(t, items, r).Results[0]
		if want := map[string]string{cveA: "affected/null"}; !reflect.DeepEqual(advisoryReasons(got), want) {
			t.Errorf("advisories = %v, want %v", advisoryReasons(got), want)
		}
	})

	t.Run("counts towards the range limit of its advisory", func(t *testing.T) {
		t.Parallel()
		r := rowsFor(t, items).cpes("acme", "widget",
			below(cveA, 4),
			below(cveB, 2), cpeAt(cveB, widgetCPE, "2.0", "3.0"), cpeAt(cveB, widgetCPE, "3.0", "4.0"),
			below(cveC, 3))
		res := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, Limits{ItemRows: 50000, AdvisoryRanges: 3})
		got := res.Results[0]
		want := map[string]string{cveA: "cannot_evaluate/too_many_ranges", cveB: "cannot_evaluate/too_many_ranges"}
		if !reflect.DeepEqual(advisoryReasons(got), want) {
			t.Errorf("advisories = %v, want %v", advisoryReasons(got), want)
		}
		if wantCounts := (Counts{CannotEvaluate: 2, NotAffected: 1}); got.Counts != wantCounts {
			t.Errorf("counts = %+v, want %+v", got.Counts, wantCounts)
		}
	})

	t.Run("counts as one row towards the item's row limit", func(t *testing.T) {
		t.Parallel()
		r := rowsFor(t, items).cpes("acme", "widget", below(cveA, 500), below(cveB, 500), cpeAt(cveC, widgetCPE, "2.0", "3.0"))
		for limit, tooMany := range map[int]bool{3: false, 2: true} {
			res := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, Limits{ItemRows: limit, AdvisoryRanges: 1000})
			got := res.Results[0]
			if over := got.Reason != nil && *got.Reason == ReasonTooManyCandidates; over != tooMany {
				t.Errorf("item limit %d: too_many_candidates = %v, want %v (counts %+v)", limit, over, tooMany, got.Counts)
			}
			if !tooMany && got.Counts.NotAffected != 3 {
				t.Errorf("item limit %d: counts = %+v, want 3 not affected", limit, got.Counts)
			}
		}
	})
}

// TestEvaluateCPERowsInOneOrder checks that an advisory's answer does not
// depend on the order its rows were read in: its reason, which is the first
// row's that cannot be compared, and the order of its matched ranges.
func TestEvaluateCPERowsInOneOrder(t *testing.T) {
	t.Parallel()
	items := parseItems(widgetItem)
	rows := []CPERow{
		widgetRange(cveA, cpeBounds{startIncluding: "1.0", endExcluding: "2.0"}),
		widgetRange(cveA, cpeBounds{startIncluding: "1.2", endExcluding: "1.9"}),
		widgetRange(cveA, cpeBounds{startIncluding: "1.0", endIncluding: "1.7"}),
		widgetExact(cveA, "1.5.0"),
		widgetRange(cveB, cpeBounds{}),
		widgetRange(cveB, cpeBounds{startIncluding: "3.0", endExcluding: "2.0"}),
		widgetExact(cveB, "-"),
	}
	var want string
	for rotation := range rows {
		order := append(slices.Clone(rows[rotation:]), rows[:rotation]...)
		if rotation%2 == 1 {
			slices.Reverse(order)
		}
		got := jsonOf(t, run(t, items, rowsFor(t, items).cpes("acme", "widget", order...)).Results[0])
		if rotation == 0 {
			want = got
			continue
		}
		if got != want {
			t.Errorf("rows in another order (rotation %d) answer differently\n got %s\nwant %s", rotation, got, want)
		}
	}
	if !strings.Contains(want, string(ReasonNoVersionBounds)) || !strings.Contains(want, `"matched_ranges_total":4`) {
		t.Errorf("answer does not hold what the order could change: %s", want)
	}
}

// leaveOutBelow returns data as the store returns it for keys: at each CPE key
// with a floor, the rows CPERowBelow reports for the floor are replaced by one
// row per CVE counting them.
func leaveOutBelow(keys Keys, data Candidates) (filtered Candidates, leftOut int) {
	filtered = data
	filtered.CPEs = make([]KeyRows[CPERow], len(data.CPEs))
	for i, kr := range data.CPEs {
		var kept []CPERow
		counts := map[string]*CPERow{}
		var order []string
		for _, row := range kr.Rows {
			if keys.CPEPrefixes[i].Floor == "" || !CPERowBelow(keys.CPEPrefixes[i].Floor, row) {
				kept = append(kept, row)
				continue
			}
			leftOut++
			if counts[row.CVEID] == nil {
				counts[row.CVEID] = &CPERow{CVEID: row.CVEID, Status: row.Status}
				order = append(order, row.CVEID)
			}
			counts[row.CVEID].Below++
		}
		for _, cve := range order {
			kept = append(kept, *counts[cve])
		}
		filtered.CPEs[i] = KeyRows[CPERow]{Rows: kept, Overflow: kr.Overflow}
	}
	return filtered, leftOut
}

// equivalenceShapes is one row of every shape cve_cpe_matches holds, around the
// versions equivalenceVersions lists.
func equivalenceShapes(cve string) []CPERow {
	return []CPERow{
		widgetExact(cve, "1.2.3"),      // exact, dotted numbers
		widgetExact(cve, "2.0"),        // exact, equal to a tested version
		widgetExact(cve, "0.5"),        // exact, low
		widgetExact(cve, "2.6.22_rc7"), // exact, suffixed
		widgetExact(cve, "2.0b10"),     // exact, suffixed on a tested version
		widgetExact(cve, `1\:2.0`),     // exact, epoch
		widgetExact(cve, "1*"),         // exact, wildcard
		widgetExact(cve, "-"),          // not applicable
		widgetRange(cve, cpeBounds{}),  // unbounded
		widgetRange(cve, cpeBounds{startIncluding: "1.0", endExcluding: "2.0"}),                        // bounded, fix
		widgetRange(cve, cpeBounds{startIncluding: "2.0", endExcluding: "3.0"}),                        // bounded, the next line
		widgetRange(cve, cpeBounds{startIncluding: "1.0", endExcluding: "1.4"}),                        // bounded, short
		widgetRange(cve, cpeBounds{endIncluding: "2.0"}),                                               // from the start, inclusive
		widgetRange(cve, cpeBounds{endExcluding: "0.9"}),                                               // from the start, low
		widgetRange(cve, cpeBounds{startExcluding: "1.5.0", endExcluding: "2.6"}),                      // start excluding
		widgetRange(cve, cpeBounds{startIncluding: "2.0"}),                                             // no end
		widgetRange(cve, cpeBounds{startIncluding: "1.0.0", endExcluding: "1.0.2zf"}),                  // suffixed end
		widgetRange(cve, cpeBounds{startIncluding: "1.0.2", endExcluding: "1.0.2zf"}),                  // bounds with no decided order
		widgetRange(cve, cpeBounds{startIncluding: "1.0b1", endIncluding: "2.6.22"}),                   // suffixed start
		widgetRange(cve, cpeBounds{startIncluding: "3.0", endExcluding: "2.0"}),                        // inverted
		widgetRange(cve, cpeBounds{startIncluding: "2.0", endExcluding: "2.0"}),                        // empty
		widgetRange(cve, cpeBounds{startIncluding: "1.0", endIncluding: "1.0"}),                        // one value
		widgetRange(cve, cpeBounds{startIncluding: "1.0", startExcluding: "1.0", endExcluding: "2.0"}), // both starts
		widgetRange(cve, cpeBounds{startIncluding: "1.0", endIncluding: "2.0", endExcluding: "2.0"}),   // both ends
		{CVEID: cve, CPE: widgetPrefix + "1.0:*:*:*:*:*:*:*", VersionEndExcluding: "3.0"},              // literal with bounds
		{CVEID: cve, CPE: widgetPrefix + "1.0:*:*:*:*:*:*"},                                            // twelve components
	}
}

var equivalenceVersions = []string{"0.5", "0.9", "1.0", "1.0.2", "1.2.3", "1.4", "1.5.0", "2.0", "2.0.1", "2.6.22",
	"2.6.22.1", "3", "6.12.0", "10.0", "1.5rc1"}

// equivalenceCNA returns the CNA entries CVE number n carries; most carry none.
func equivalenceCNA(n int) []CNAVersion {
	switch n % 11 {
	case 1:
		return []CNAVersion{{Version: "0", LessThan: "2.5", Status: "affected", VersionType: "custom"}}
	case 2:
		return []CNAVersion{{Version: "1.0.0", LessThan: "7.0.0", Status: "affected", VersionType: "semver"}}
	case 3:
		return []CNAVersion{{Version: "unspecified", Status: "affected"}}
	case 4:
		return []CNAVersion{{Version: "1.0", LessThan: "1.*", Status: "affected", VersionType: "custom"}}
	case 5:
		return []CNAVersion{{Version: "0", LessThan: "1.4", Status: "affected", VersionType: "custom"},
			{Version: "2.0", LessThanOrEqual: "2.6.22", Status: "affected", VersionType: "custom"}}
	case 6:
		return []CNAVersion{{Version: "1.0", Status: "affected", VersionType: "custom",
			Changes: []CNAChange{{At: "1.4", Status: "unaffected"}}, LessThan: "*"}}
	}
	return nil
}

// equivalenceCVE is one CVE's stored rows for acme:widget.
type equivalenceCVE struct {
	rows []CPERow
	cna  []CNARow
	near []CNANearRow
}

// equivalenceCVEs returns CVEs holding every row shape alone, every pair of
// shapes, runs of one shape that pass a range limit of 6, and random groups of
// three to five shapes. Some also carry CNA entries, a nearby-name row or a
// retracted status.
func equivalenceCVEs() []equivalenceCVE {
	var cves []equivalenceCVE
	add := func(rows ...CPERow) {
		n := len(cves) + 1
		cve := fmt.Sprintf("CVE-2026-%05d", n)
		status := ""
		if n%13 == 0 {
			status = "REJECTED"
		}
		c := equivalenceCVE{}
		for _, row := range rows {
			row.CVEID, row.Status = cve, status
			c.rows = append(c.rows, row)
		}
		if versions := equivalenceCNA(n); versions != nil {
			row := cnaAt(cve, "acme", "widget", versions...)
			row.Status = status
			c.cna = append(c.cna, row)
		}
		if n%17 == 0 {
			c.near = append(c.near, CNANearRow{CVEID: cve, Vendor: "acme", Product: "widget pro", Status: status})
		}
		cves = append(cves, c)
	}
	shapes := equivalenceShapes("")
	for _, a := range shapes {
		add(a)
	}
	for _, a := range shapes {
		for _, b := range shapes {
			add(a, b)
		}
	}
	for _, a := range shapes {
		add(a, a, a, a, a, a, a)
	}
	for g := range 300 {
		rows := make([]CPERow, 3+g%3)
		for i := range rows {
			rows[i] = shapes[(g*7+i*i*5+i*11)%len(shapes)]
		}
		add(rows...)
	}
	return cves
}

// equivalenceRequests are the versions asked of the product in one request:
// each dotted-number version alone, so its own version is the floor; requests
// of several, where the floor is the lowest and lies below the others; and one
// with a version that is not dotted numbers, which leaves the key no floor.
func equivalenceRequests() [][]string {
	dotted := equivalenceVersions[:len(equivalenceVersions)-1]
	var requests [][]string
	for _, v := range dotted {
		requests = append(requests, []string{v})
	}
	return append(requests,
		dotted,
		[]string{"10.0", "2.6.22.1", "2.6.22", "6.12.0"},
		[]string{"3", "1.4", "2.0.1"},
		[]string{"6.12.0", "1.0.2", "1.0"},
		equivalenceVersions,
	)
}

// TestEvaluateLeavingOutRowsBelowChangesNoAnswer evaluates each request twice:
// from every row of the product, and from the rows the store returns once it
// leaves out the rows lying wholly below the key's floor, the lowest version
// in the request. The two results must be equal. CVEs are evaluated 90 at a
// time, so that every advisory is listed and compared, not only the first 100.
func TestEvaluateLeavingOutRowsBelowChangesNoAnswer(t *testing.T) {
	t.Parallel()
	limits := Limits{ItemRows: 1 << 30, AdvisoryRanges: 6}
	cves := equivalenceCVEs()

	var totals Counts
	leftOut, fixes, tooMany, floors := 0, 0, 0, 0
	for _, versions := range equivalenceRequests() {
		var raws []RawItem
		for _, v := range versions {
			raws = append(raws, RawItem{CPE: widgetCPE, Version: v})
		}
		items := parseItems(raws...)
		for chunk := range slices.Chunk(cves, 90) {
			r := rowsFor(t, items)
			for _, c := range chunk {
				r.cpes("acme", "widget", c.rows...).cnaName("acme", "widget", false, c.cna...)
				if len(r.keys.CNANear) > 0 {
					r.near("acme", c.near...)
				}
			}
			want := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, limits)

			filtered, n := leaveOutBelow(r.keys, r.data)
			leftOut += n
			got, err := evaluateItems(newWorkMeter(context.Background()), items, filtered, feedsWith(true), nil, limits)
			if err != nil {
				t.Fatalf("evaluateItems on the filtered rows: %v", err)
			}

			for i, res := range want.Results {
				if res.AdvisoriesTruncated {
					t.Fatalf("version %s: advisories truncated, so not all are compared", items[i].Version)
				}
				if !reflect.DeepEqual(got.Results[i], res) {
					t.Errorf("request %v, version %s: result differs once rows below the floor are left out\n got %s\nwant %s",
						versions, items[i].Version, jsonOf(t, got.Results[i]), jsonOf(t, res))
				}
				totals.Affected += res.Counts.Affected
				totals.CannotEvaluate += res.Counts.CannotEvaluate
				totals.NotAffected += res.Counts.NotAffected
				totals.Retracted += res.Counts.Retracted
				for _, adv := range res.Advisories {
					if adv.FixedVersion != nil {
						fixes++
					}
					if adv.Reason != nil && *adv.Reason == ReasonTooManyRanges {
						tooMany++
					}
				}
			}
		}
		if KeysFor(items).CPEPrefixes[0].Floor != "" {
			floors++
		}
	}

	// The comparison means nothing unless rows were left out and the answers vary.
	if floors < len(equivalenceVersions) || leftOut < 10000 {
		t.Errorf("%d requests had a floor and %d rows were left out, want most requests and many rows", floors, leftOut)
	}
	if totals.Affected == 0 || totals.CannotEvaluate == 0 || totals.NotAffected == 0 || totals.Retracted == 0 || fixes == 0 || tooMany == 0 {
		t.Errorf("answers do not vary enough to compare: counts %+v, %d fixes, %d over the range limit", totals, fixes, tooMany)
	}
}

// TestCNAOrdersNeverPlaceADottedNumberBelowNumericOrder checks what lets a row
// lying below the version go unread during fix validation: a CNA fix candidate
// is above the version in its entry's own order, and for dotted numbers no CNA
// order places a version below one that NumericOrder places above it. The
// candidate is therefore at or above the version in NumericOrder, where a row
// below the version answers NotAffected.
func TestCNAOrdersNeverPlaceADottedNumberBelowNumericOrder(t *testing.T) {
	t.Parallel()
	// Every version of one to three components from these values, and some of four.
	values := []string{"0", "00", "1", "01", "2", "10", "099", "100"}
	var dotted []string
	for _, a := range values {
		dotted = append(dotted, a, "2026."+a+".0."+a)
		for _, b := range values {
			dotted = append(dotted, a+"."+b)
			for _, c := range values {
				dotted = append(dotted, a+"."+b+"."+c)
			}
		}
	}
	compared := map[string]int{}
	for _, a := range dotted {
		for _, b := range dotted {
			numeric, err := version.NumericOrder(a, b)
			if err != nil {
				t.Fatalf("NumericOrder(%q, %q): %v", a, b, err)
			}
			for _, versionType := range []string{"semver", "python", "maven", "rpm", "custom", ""} {
				c, err := orderFor(versionType)(a, b)
				if err != nil {
					continue
				}
				compared[versionType]++
				if c < 0 && numeric > 0 {
					t.Errorf("%q order places %s below %s, but NumericOrder places it above", versionType, a, b)
				}
			}
		}
	}
	for _, versionType := range []string{"semver", "python", "maven", "rpm", "custom", ""} {
		if compared[versionType] == 0 {
			t.Errorf("%q order compared no pair", versionType)
		}
	}
}
