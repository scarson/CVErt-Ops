// ABOUTME: Integration tests for the CPE lookup leaving out rows whose ranges lie wholly below a key's floor.
// ABOUTME: Pins the SQL rule to check.CPERowBelow, the per-key limit on what remains, and that no answer changes.
package store_test

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const gizmoPrefix = "cpe:2.3:a:acme:gizmo:"

// gizmoExact is a vulnerable match naming one version component of acme:gizmo;
// gizmoRange is one with the wildcard component and the given bounds.
func gizmoExact(component string) feed.CPEMatch {
	cpe := gizmoPrefix + component + ":*:*:*:*:*:*:*"
	return feed.CPEMatch{CPE: cpe, CPENormalized: cpe, Vulnerable: true}
}

func gizmoRange(startIncluding, startExcluding, endIncluding, endExcluding string) feed.CPEMatch {
	m := gizmoExact("*")
	m.VersionStartIncluding, m.VersionStartExcluding = startIncluding, startExcluding
	m.VersionEndIncluding, m.VersionEndExcluding = endIncluding, endExcluding
	return m
}

// belowBounds are bounds of every kind the rule reads or refuses to read:
// dotted numbers around the tested versions, suffixed releases, leading zeros,
// numbers longer than any integer type, epochs, wildcards, encoded and escaped
// characters, and text with no leading digit.
var belowBounds = []string{
	"0", "0.0", "0.9", "1", "1.0", "1.0.2", "2.0", "2.0.0.1", "2.6.22", "3", "09.5", "9.5", "10",
	"1.0b1", "1.0.2zf", "2.0b10", "2.6.22_rc7", "2.6.22-rc1", "2.6_test9_cvs",
	"99999999999999999999999999999999999999.5", "100000000000000000000000000000000000000",
	"1:2.0", `1\:2.0`, "1!2.0", "1*", "1?", "1%3a2.4", `1.2\(55\)se`, "v1.2", "rc1", "1..2", "1.", ".5",
	strings.Repeat("1", 257), strings.Repeat("1", 256),
}

var belowVersions = []string{"0", "0.5", "1.0", "1.0.2", "2.0", "2.6.22", "2.6.22.1", "3", "9.5", "10.0",
	"100000000000000000000000000000000000000.1", "6.12.0-rc1"}

// belowFloors are belowVersions as key floors, with "" for the last, which is
// not dotted numbers.
var belowFloors = append(slices.Clone(belowVersions[:len(belowVersions)-1]), "")

// belowMatches returns matches of every shape over belowBounds: each bound as an
// exact version component, each pair as the start and end of a range in the
// four inclusive and exclusive combinations, each bound as a lone start or end,
// and the shapes that state no range.
func belowMatches() []feed.CPEMatch {
	matches := []feed.CPEMatch{
		gizmoExact("*"), gizmoExact("-"),
		gizmoRange("1.0", "1.0", "", "2.0"), gizmoRange("1.0", "", "2.0", "2.0"), gizmoRange("", "", "2.0", "2.0"),
		{CPE: gizmoPrefix + "1.0:*:*:*:*:*:*", CPENormalized: gizmoPrefix + "1.0:*:*:*:*:*:*", Vulnerable: true},
		{CPE: gizmoPrefix + `1.0\:*:*:*:*:*:*:*`, CPENormalized: gizmoPrefix + `1.0\:*:*:*:*:*:*:*`, Vulnerable: true},
		{CPE: gizmoPrefix + `1.0:*:*:*:*:joomla\!:*:*`, CPENormalized: gizmoPrefix + `1.0:*:*:*:*:joomla\!:*:*`, Vulnerable: true},
		{CPE: gizmoPrefix + `1.0:rc1:*:*:*:*:\:\\:*`, CPENormalized: gizmoPrefix + `1.0:rc1:*:*:*:*:\:\\:*`, Vulnerable: true},
		{CPE: gizmoPrefix + `1.0:*:*:*:*:*:*:*:*`, CPENormalized: gizmoPrefix + `1.0:*:*:*:*:*:*:*:*`, Vulnerable: true},
	}
	literal := gizmoExact("1.0")
	literal.VersionEndExcluding = "2.0"
	matches = append(matches, literal)
	for _, a := range belowBounds {
		if !strings.Contains(a, ":") || strings.Contains(a, `\:`) {
			matches = append(matches, gizmoExact(a))
		}
		matches = append(matches, gizmoRange(a, "", "", ""), gizmoRange("", a, "", ""), gizmoRange("", "", a, ""), gizmoRange("", "", "", a))
		for _, b := range belowBounds {
			matches = append(matches, gizmoRange(a, "", b, ""), gizmoRange(a, "", "", b), gizmoRange("", a, b, ""), gizmoRange("", a, "", b))
		}
	}
	return matches
}

// ingestGizmo stores matches 40 to a CVE and returns the stored rows, with the
// CVE of each.
func ingestGizmo(t *testing.T, tdb *testutil.TestDB, matches []feed.CPEMatch) []check.CPERow {
	t.Helper()
	var rows []check.CPERow
	n := 0
	for chunk := range slices.Chunk(matches, 40) {
		n++
		cve := fmt.Sprintf("CVE-2026-%05d", 70000+n)
		ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: cve, CPEMatches: chunk})
		for _, m := range chunk {
			rows = append(rows, check.CPERow{CVEID: cve, CPE: m.CPENormalized,
				VersionStartIncluding: m.VersionStartIncluding, VersionStartExcluding: m.VersionStartExcluding,
				VersionEndIncluding: m.VersionEndIncluding, VersionEndExcluding: m.VersionEndExcluding})
		}
	}
	return rows
}

// gizmoKeys returns one key of acme:gizmo per floor. A floor here may be any
// version, with more components than check.KeysFor gives one, so that the SQL
// rule is checked on them too; "" is the key of a version that is not dotted
// numbers.
func gizmoKeys(floors ...string) check.Keys {
	product := productKeys("a", "acme", "gizmo").CPEPrefixes[0]
	var keys check.Keys
	for _, floor := range floors {
		keys.CPEPrefixes = append(keys.CPEPrefixes, check.CPEKey{Lo: product.Lo, Hi: product.Hi, Floor: floor})
	}
	return keys
}

func sortCPERows(rows []check.CPERow) []check.CPERow {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b check.CPERow) int {
		return strings.Compare(fmt.Sprintf("%+v", a), fmt.Sprintf("%+v", b))
	})
	return sorted
}

// TestReadCheckCandidates_CPERowsBelow checks the SQL rule against
// check.CPERowBelow over every row shape: for each floor, the lookup returns
// exactly the rows the Go rule keeps, and for each CVE one row counting the
// rows it leaves out. A key with no floor returns every row.
func TestReadCheckCandidates_CPERowsBelow(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	stored := ingestGizmo(t, tdb, belowMatches())

	keys := gizmoKeys(belowFloors...)
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	leftOut := 0
	for i, key := range keys.CPEPrefixes {
		var want []check.CPERow
		counts := map[string]int{}
		for _, row := range stored {
			if key.Floor != "" && check.CPERowBelow(key.Floor, row) {
				counts[row.CVEID]++
				leftOut++
				continue
			}
			want = append(want, row)
		}
		for cve, n := range counts {
			want = append(want, check.CPERow{CVEID: cve, Below: n})
		}
		got := cands.CPEs[i]
		if got.Overflow {
			t.Errorf("floor %q: key overflowed", key.Floor)
		}
		gotRows, wantRows := sortCPERows(got.Rows), sortCPERows(want)
		if reflect.DeepEqual(gotRows, wantRows) {
			continue
		}
		t.Errorf("floor %q: %d rows, want %d", key.Floor, len(gotRows), len(wantRows))
		for _, row := range gotRows {
			if !slices.Contains(wantRows, row) {
				t.Errorf("floor %q: unexpected row %+v", key.Floor, row)
			}
		}
		for _, row := range wantRows {
			if !slices.Contains(gotRows, row) {
				t.Errorf("floor %q: missing row %+v", key.Floor, row)
			}
		}
	}
	if leftOut < 1000 {
		t.Errorf("rows left out = %d, want many: the comparison checked too little", leftOut)
	}
}

// TestReadCheckCandidates_CPERowsBelowChangeNoAnswer evaluates the same items
// from two reads of the same rows: one that leaves out the rows below the floor
// of each item's version, and one that reads every row.
func TestReadCheckCandidates_CPERowsBelowChangeNoAnswer(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestGizmo(t, tdb, belowMatches())
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79001", Status: "REJECTED", CPEMatches: []feed.CPEMatch{gizmoExact("0.1")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79002", CPEMatches: []feed.CPEMatch{
		gizmoRange("1.0", "", "", "1.4"), gizmoRange("2.0", "", "", "2.6")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79003", CPEMatches: []feed.CPEMatch{gizmoExact("0.1"), gizmoExact("0.2")}})

	var items []check.Item
	for i, v := range belowVersions {
		items = append(items, check.ParseItem(i, check.RawItem{CPE: gizmoPrefix + "*:*:*:*:*:*:*:*", Version: v}))
	}
	keys := check.KeysFor(items)
	every := keys
	every.CPEPrefixes = slices.Clone(keys.CPEPrefixes)
	for i := range every.CPEPrefixes {
		every.CPEPrefixes[i].Floor = ""
	}

	// A range limit of 30 holds every 40-row CVE at too_many_ranges, which
	// needs the count of the rows left out; 1,000 lets each be evaluated.
	orgID := checkOrg(t, tdb)
	var want check.Results
	for _, ranges := range []int{30, 1000} {
		limits := check.Limits{ItemRows: 1 << 30, AdvisoryRanges: ranges}
		evaluate := func(keys check.Keys) check.Results {
			cands, enrichment, feeds := readCheck(t, tdb, orgID, keys, store.DefaultCheckLimits, nil)
			res, err := check.EvaluateWithLimits(context.Background(), items, cands, check.FeedStatuses(feeds, time.Now()), enrichment, limits)
			if err != nil {
				t.Fatalf("EvaluateWithLimits: %v", err)
			}
			return res
		}
		var got check.Results
		got, want = evaluate(keys), evaluate(every)
		for i := range items {
			if !reflect.DeepEqual(got.Results[i], want.Results[i]) {
				t.Errorf("range limit %d, version %s: result differs once rows below it are left out\n got %+v\nwant %+v",
					ranges, items[i].Version, got.Results[i], want.Results[i])
			}
		}
	}
	var totals check.Counts
	for _, res := range want.Results {
		totals.Affected += res.Counts.Affected
		totals.CannotEvaluate += res.Counts.CannotEvaluate
		totals.NotAffected += res.Counts.NotAffected
		totals.Retracted += res.Counts.Retracted
	}
	if totals.Affected == 0 || totals.CannotEvaluate == 0 || totals.NotAffected == 0 || totals.Retracted == 0 {
		t.Errorf("answers do not vary enough to compare: counts %+v", totals)
	}
}

// TestReadCheckCandidates_CPERowsBelowKeyLimit checks that the per-key limit
// counts what the lookup returns: a product with more rows than the limit is
// read in full when most lie below the floor of the item's version, each CVE's
// left-out rows counting as one, and the item is then answered.
func TestReadCheckCandidates_CPERowsBelowKeyLimit(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	high := "HIGH"
	for n := range 5 {
		var old []feed.CPEMatch
		for patch := range 8 {
			old = append(old, gizmoExact(fmt.Sprintf("2.6.%d.%d", n, patch)))
		}
		ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: fmt.Sprintf("CVE-2026-7100%d", n), Severity: &high, CPEMatches: old})
	}
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-71010", Status: "REJECTED", CPEMatches: []feed.CPEMatch{gizmoExact("2.4.1")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-71011", CPEMatches: []feed.CPEMatch{
		gizmoRange("6.1", "", "", "6.1.50"), gizmoRange("6.6", "", "", "6.12.4")}})

	items := []check.Item{
		check.ParseItem(0, check.RawItem{CPE: gizmoPrefix + "*:*:*:*:*:*:*:*", Version: "6.12.0"}),
		check.ParseItem(1, check.RawItem{CPE: gizmoPrefix + "*:*:*:*:*:*:*:*", Version: "6.12.0-rc1"}),
	}
	keys := check.KeysFor(items)
	orgID := checkOrg(t, tdb)

	// 43 stored rows. For 6.12.0 the lookup returns the range that contains it
	// and one row for each of the 7 CVEs with rows below it.
	limits := store.DefaultCheckLimits
	limits.KeyRows = 8
	cands, enrichment, feeds := readCheck(t, tdb, orgID, keys, limits, nil)
	if got := cands.CPEs[0]; got.Overflow || len(got.Rows) != 8 {
		t.Errorf("6.12.0: %d rows, overflow %v; want 8 rows and no overflow", len(got.Rows), got.Overflow)
	}
	if got := cands.CPEs[1]; !got.Overflow || len(got.Rows) != 8 {
		t.Errorf("6.12.0-rc1, which reads every row: %d rows, overflow %v; want 8 rows and overflow", len(got.Rows), got.Overflow)
	}
	leftOut := map[string]check.CPERow{}
	for _, row := range cands.CPEs[0].Rows {
		if row.Below > 0 {
			leftOut[row.CVEID] = row
		}
	}
	if got, want := leftOut["CVE-2026-71003"], (check.CPERow{CVEID: "CVE-2026-71003", Below: 8}); got != want {
		t.Errorf("rows left out of CVE-2026-71003 = %+v, want %+v", got, want)
	}
	if got, want := leftOut["CVE-2026-71010"], (check.CPERow{CVEID: "CVE-2026-71010", Status: "REJECTED", Below: 1}); got != want {
		t.Errorf("rows left out of the rejected CVE = %+v, want %+v", got, want)
	}
	if got, want := leftOut["CVE-2026-71011"], (check.CPERow{CVEID: "CVE-2026-71011", Below: 1}); got != want {
		t.Errorf("rows left out of the CVE with a range that contains the version = %+v, want %+v", got, want)
	}
	if e := enrichment["CVE-2026-71003"]; e.Severity == nil || *e.Severity != high {
		t.Errorf("enrichment of a CVE with only left-out rows = %+v, want severity %s", e, high)
	}

	res, err := check.Evaluate(context.Background(), items, cands, check.FeedStatuses(feeds, time.Now()), enrichment)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	answered, refused := res.Results[0], res.Results[1]
	if want := (check.Counts{Affected: 1, NotAffected: 5, Retracted: 1}); answered.Status != check.StatusAffected || answered.Counts != want {
		t.Errorf("6.12.0: status %s, counts %+v; want affected, %+v", answered.Status, answered.Counts, want)
	}
	if len(answered.Advisories) != 1 || answered.Advisories[0].FixedVersion == nil || *answered.Advisories[0].FixedVersion != "6.12.4" {
		t.Errorf("6.12.0: advisories %+v, want CVE-2026-71011 fixed in 6.12.4", answered.Advisories)
	}
	if refused.Reason == nil || *refused.Reason != check.ReasonTooManyCandidates {
		t.Errorf("6.12.0-rc1: status %s, reason %v; want too_many_candidates", refused.Status, refused.Reason)
	}

	// One row fewer and the key is over its limit: the rows standing for
	// left-out rows count towards it.
	limits.KeyRows = 7
	cands, _, _ = readCheck(t, tdb, orgID, keys, limits, nil)
	if got := cands.CPEs[0]; !got.Overflow {
		t.Errorf("6.12.0 with a limit of 7: %d rows and no overflow, want overflow", len(got.Rows))
	}
}
