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
	// 257 bytes of dotted numbers below every tested floor: one byte over the
	// length a bound may have, so it is never left out.
	"1." + strings.Repeat("0", 255),
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

// TestReadCheckCandidates_CPERowsBelowEscapedColon checks a CPE whose vendor
// holds an escaped colon. Split at every colon it has 13 parts with 2.0 sixth,
// which would be an exact release below the floor; split as a CPE it has 12
// components, states no range, and must be returned.
func TestReadCheckCandidates_CPERowsBelowEscapedColon(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	const cpe = `cpe:2.3:a:v\:1:2.0:*:*:*:*:*:*:*`
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-72001",
		CPEMatches: []feed.CPEMatch{{CPE: cpe, CPENormalized: cpe, Vulnerable: true}}})

	keys := check.Keys{CPEPrefixes: []check.CPEKey{{Lo: `cpe:2.3:a:v\:1:2.0:`, Hi: `cpe:2.3:a:v\:1:2.0;`, Floor: "6.12.0"}}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)
	want := []check.CPERow{{CVEID: "CVE-2026-72001", CPE: cpe}}
	if got := cands.CPEs[0].Rows; !reflect.DeepEqual(got, want) {
		t.Errorf("rows = %+v, want the stored row %+v", got, want)
	}
	if check.CPERowBelow("6.12.0", want[0]) {
		t.Errorf("CPERowBelow reports %s, which has 12 components", cpe)
	}
}

// gizmoItems returns one item of acme:gizmo per version.
func gizmoItems(versions ...string) []check.Item {
	items := make([]check.Item, len(versions))
	for i, v := range versions {
		items[i] = check.ParseItem(i, check.RawItem{CPE: gizmoPrefix + "*:*:*:*:*:*:*:*", Version: v})
	}
	return items
}

// TestReadCheckCandidates_CPERowsBelowChangeNoAnswer evaluates the same items
// from two reads of the same rows: one that leaves out the rows below the
// product key's floor, the lowest version in the request, and one that reads
// every row. The requests are each version alone, all the dotted-number
// versions together, and all with one that is not dotted numbers.
func TestReadCheckCandidates_CPERowsBelowChangeNoAnswer(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestGizmo(t, tdb, belowMatches())
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79001", Status: "REJECTED", CPEMatches: []feed.CPEMatch{gizmoExact("0.1")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79002", CPEMatches: []feed.CPEMatch{
		gizmoRange("1.0", "", "", "1.4"), gizmoRange("2.0", "", "", "2.6")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-79003", CPEMatches: []feed.CPEMatch{gizmoExact("0.1"), gizmoExact("0.2")}})

	dotted := belowVersions[:len(belowVersions)-1]
	requests := [][]string{dotted, belowVersions}
	for _, v := range dotted {
		requests = append(requests, []string{v})
	}

	orgID := checkOrg(t, tdb)
	var totals check.Counts
	floors := 0
	for _, versions := range requests {
		items := gizmoItems(versions...)
		keys := check.KeysFor(items)
		if len(keys.CPEPrefixes) != 1 {
			t.Fatalf("request %v: %d CPE keys, want one for the product", versions, len(keys.CPEPrefixes))
		}
		if keys.CPEPrefixes[0].Floor != "" {
			floors++
		}
		every := keys
		every.CPEPrefixes = []check.CPEKey{{Lo: keys.CPEPrefixes[0].Lo, Hi: keys.CPEPrefixes[0].Hi}}

		// A range limit of 30 holds every 40-row CVE at too_many_ranges, which
		// needs the count of the rows left out; 1,000 lets each be evaluated.
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
			got, want := evaluate(keys), evaluate(every)
			for i := range items {
				if !reflect.DeepEqual(got.Results[i], want.Results[i]) {
					t.Errorf("request %v, range limit %d, version %s: result differs once rows below the floor are left out\n got %+v\nwant %+v",
						versions, ranges, items[i].Version, got.Results[i], want.Results[i])
				}
				totals.Affected += want.Results[i].Counts.Affected
				totals.CannotEvaluate += want.Results[i].Counts.CannotEvaluate
				totals.NotAffected += want.Results[i].Counts.NotAffected
				totals.Retracted += want.Results[i].Counts.Retracted
			}
		}
	}
	if floors != len(requests)-1 {
		t.Errorf("%d of %d requests had a floor, want all but the one with a version that is not dotted numbers", floors, len(requests))
	}
	if totals.Affected == 0 || totals.CannotEvaluate == 0 || totals.NotAffected == 0 || totals.Retracted == 0 {
		t.Errorf("answers do not vary enough to compare: counts %+v", totals)
	}
}

// ingestOldGizmo stores a product of 43 rows, most of them old: 5 CVEs of 8
// exact 2.6.x releases each, a rejected CVE with one old release, and a CVE
// with one range ending at 6.1.50 and one ending at 6.12.4.
func ingestOldGizmo(t *testing.T, tdb *testutil.TestDB, severity *string) {
	t.Helper()
	for n := range 5 {
		var old []feed.CPEMatch
		for patch := range 8 {
			old = append(old, gizmoExact(fmt.Sprintf("2.6.%d.%d", n, patch)))
		}
		ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: fmt.Sprintf("CVE-2026-7100%d", n), Severity: severity, CPEMatches: old})
	}
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-71010", Status: "REJECTED", CPEMatches: []feed.CPEMatch{gizmoExact("2.4.1")}})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-71011", CPEMatches: []feed.CPEMatch{
		gizmoRange("6.1", "", "", "6.1.50"), gizmoRange("6.6", "", "", "6.12.4")}})
}

// TestReadCheckCandidates_CPERowsBelowKeyLimit checks that the per-key limit
// counts what the lookup returns: a product with more rows than the limit is
// read in full when most lie below the lowest version asked of it, each CVE's
// left-out rows counting as one, and its items are then answered. A request
// that also asks a version that is not dotted numbers reads every row, and is
// over the limit as the product was before rows were left out.
func TestReadCheckCandidates_CPERowsBelowKeyLimit(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	high := "HIGH"
	ingestOldGizmo(t, tdb, &high)
	orgID := checkOrg(t, tdb)

	// For 6.12.0 and 6.13.1 the lookup returns the range that contains 6.12.0
	// and one row for each of the 7 CVEs with rows below it.
	items := gizmoItems("6.13.1", "6.12.0")
	keys := check.KeysFor(items)
	limits := store.DefaultCheckLimits
	limits.KeyRows = 8
	cands, enrichment, feeds := readCheck(t, tdb, orgID, keys, limits, nil)
	if got := cands.CPEs[0]; len(cands.CPEs) != 1 || got.Overflow || len(got.Rows) != 8 {
		t.Fatalf("6.13.1 and 6.12.0: %d keys, %d rows, overflow %v; want one key of 8 rows and no overflow", len(cands.CPEs), len(got.Rows), got.Overflow)
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
	past, inside := res.Results[0], res.Results[1]
	if want := (check.Counts{Affected: 1, NotAffected: 5, Retracted: 1}); inside.Status != check.StatusAffected || inside.Counts != want {
		t.Errorf("6.12.0: status %s, counts %+v; want affected, %+v", inside.Status, inside.Counts, want)
	}
	if len(inside.Advisories) != 1 || inside.Advisories[0].FixedVersion == nil || *inside.Advisories[0].FixedVersion != "6.12.4" {
		t.Errorf("6.12.0: advisories %+v, want CVE-2026-71011 fixed in 6.12.4", inside.Advisories)
	}
	if want := (check.Counts{NotAffected: 6, Retracted: 1}); past.Counts != want || past.Reason != nil && *past.Reason == check.ReasonTooManyCandidates {
		t.Errorf("6.13.1: counts %+v, reason %v; want %+v and no too_many_candidates", past.Counts, past.Reason, want)
	}

	// One row fewer and the key is over its limit: the rows standing for
	// left-out rows count towards it.
	limits.KeyRows = 7
	cands, _, _ = readCheck(t, tdb, orgID, keys, limits, nil)
	if got := cands.CPEs[0]; !got.Overflow {
		t.Errorf("a limit of 7: %d rows and no overflow, want overflow", len(got.Rows))
	}

	// A version that is not dotted numbers needs every row, so the product's
	// one key has no floor and every item of the product is over the limit.
	limits.KeyRows = 8
	items = gizmoItems("6.12.0", "6.12.0-rc1")
	cands, enrichment, feeds = readCheck(t, tdb, orgID, check.KeysFor(items), limits, nil)
	if got := cands.CPEs[0]; len(cands.CPEs) != 1 || !got.Overflow || len(got.Rows) != 8 {
		t.Fatalf("6.12.0 and 6.12.0-rc1: %d keys, %d rows, overflow %v; want one key of 8 rows and overflow", len(cands.CPEs), len(got.Rows), got.Overflow)
	}
	res, err = check.Evaluate(context.Background(), items, cands, check.FeedStatuses(feeds, time.Now()), enrichment)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	for _, r := range res.Results {
		if r.Reason == nil || *r.Reason != check.ReasonTooManyCandidates {
			t.Errorf("%s beside 6.12.0-rc1: status %s, reason %v; want too_many_candidates", r.Component.Version, r.Status, r.Reason)
		}
	}
}

// TestReadCheckCandidates_CPERowsBelowNeverReadMore checks that a key with a
// floor never reads more rows than the same key with none: stored rows and CVE
// counts share one LIMIT. With a key limit of 3, the product's 43 rows, and
// its 1 stored row and 7 counts under a floor, each stop at 4 rows read.
func TestReadCheckCandidates_CPERowsBelowNeverReadMore(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestOldGizmo(t, tdb, nil)
	orgID := checkOrg(t, tdb)

	limits := store.DefaultCheckLimits
	limits.KeyRows, limits.RequestRows = 3, 4
	for _, floor := range []string{"", "6.12.0"} {
		cands, _, _ := readCheck(t, tdb, orgID, gizmoKeys(floor), limits, nil)
		if got := cands.CPEs[0]; !got.Overflow || len(got.Rows) != 3 {
			t.Errorf("floor %q: %d rows, overflow %v; want 3 rows and overflow", floor, len(got.Rows), got.Overflow)
		}
	}
}
