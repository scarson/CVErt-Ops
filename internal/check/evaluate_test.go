// ABOUTME: Tests Evaluate: item status from advisory verdicts, limits, retraction, listing, feeds and the response shape.
// ABOUTME: Rows are placed at the keys KeysFor gives, as the store reads them; no database is used.
package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

func parseItems(raws ...RawItem) []Item {
	items := make([]Item, len(raws))
	for i, raw := range raws {
		items[i] = ParseItem(i, raw)
	}
	return items
}

// testRows places rows at the keys KeysFor gives for a request's items, as the
// store would return them. Each method fails the test when the key is missing.
type testRows struct {
	t    *testing.T
	keys Keys
	data Candidates
}

func rowsFor(t *testing.T, items []Item) *testRows {
	t.Helper()
	keys := KeysFor(items)
	return &testRows{t: t, keys: keys, data: Candidates{
		Packages:       make([]KeyRows[PackageRow], len(keys.Packages)),
		CPEs:           make([]KeyRows[CPERow], len(keys.CPEPrefixes)),
		CNANames:       make([]KeyRows[CNARow], len(keys.CNANames)),
		CNAPackageKeys: make([]KeyRows[CNARow], len(keys.CNAPackageKeys)),
		CNANear:        make([]KeyRows[CNANearRow], len(keys.CNANear)),
	}}
}

func (r *testRows) found(kind string, i int) int {
	r.t.Helper()
	if i < 0 {
		r.t.Fatalf("KeysFor gave no %s key", kind)
	}
	return i
}

func (r *testRows) packageKey(eco, name string) int {
	r.t.Helper()
	return r.found("package", slices.Index(r.keys.Packages, PackageKey{Ecosystem: eco, Name: ecosystem.FoldPackageName(eco, name)}))
}

func (r *testRows) packages(eco, name string, rows ...PackageRow) *testRows {
	r.t.Helper()
	i := r.packageKey(eco, name)
	for _, row := range rows {
		row.Ecosystem, row.PackageName = eco, name
		r.data.Packages[i].Rows = append(r.data.Packages[i].Rows, row)
	}
	return r
}

func (r *testRows) overflowPackages(eco, name string) *testRows {
	r.t.Helper()
	r.data.Packages[r.packageKey(eco, name)].Overflow = true
	return r
}

// cpeKeys returns the index of every key of the product: one per item version.
func (r *testRows) cpeKeys(vendor, product string) []int {
	r.t.Helper()
	lo := "cpe:2.3:a:" + vendor + ":" + product + ":"
	var found []int
	for i, k := range r.keys.CPEPrefixes {
		if k.Lo == lo {
			found = append(found, i)
		}
	}
	if len(found) == 0 {
		r.t.Fatalf("KeysFor gave no CPE key")
	}
	return found
}

// cpes adds rows at every key of the product, as the product's stored rows are
// read for each item version.
func (r *testRows) cpes(vendor, product string, rows ...CPERow) *testRows {
	r.t.Helper()
	for _, i := range r.cpeKeys(vendor, product) {
		r.data.CPEs[i].Rows = append(r.data.CPEs[i].Rows, rows...)
	}
	return r
}

func (r *testRows) overflowCPEs(vendor, product string) *testRows {
	r.t.Helper()
	for _, i := range r.cpeKeys(vendor, product) {
		r.data.CPEs[i].Overflow = true
	}
	return r
}

// cnaNameKey returns the index of the exact CNA name key for vendor and
// product, or of the prefix key when prefix is set.
func (r *testRows) cnaNameKey(vendor, product string, prefix bool) int {
	r.t.Helper()
	return r.found("CNA name", slices.IndexFunc(r.keys.CNANames, func(k CNANameKey) bool {
		if prefix {
			return k.FullVendor == vendor && k.FullProduct == "" && k.Lo == product
		}
		return k.FullVendor == vendor && k.FullProduct == product
	}))
}

// cnaName adds rows at the exact CNA name key for vendor and product, or at the
// prefix key when prefix is set.
func (r *testRows) cnaName(vendor, product string, prefix bool, rows ...CNARow) *testRows {
	r.t.Helper()
	i := r.cnaNameKey(vendor, product, prefix)
	r.data.CNANames[i].Rows = append(r.data.CNANames[i].Rows, rows...)
	return r
}

func (r *testRows) overflowCNAName(vendor, product string, prefix bool) *testRows {
	r.t.Helper()
	r.data.CNANames[r.cnaNameKey(vendor, product, prefix)].Overflow = true
	return r
}

func (r *testRows) cnaPackage(key string, rows ...CNARow) *testRows {
	r.t.Helper()
	i := r.found("CNA package", slices.Index(r.keys.CNAPackageKeys, key))
	r.data.CNAPackageKeys[i].Rows = append(r.data.CNAPackageKeys[i].Rows, rows...)
	return r
}

func (r *testRows) near(vendor string, rows ...CNANearRow) *testRows {
	r.t.Helper()
	i := r.found("nearby-name", slices.IndexFunc(r.keys.CNANear, func(k CNANearKey) bool { return k.FullVendor == vendor }))
	r.data.CNANear[i].Rows = append(r.data.CNANear[i].Rows, rows...)
	return r
}

// nearFragment adds rows at the nearby-name key for vendor and fragment.
func (r *testRows) nearFragment(vendor, fragment string, rows ...CNANearRow) *testRows {
	r.t.Helper()
	i := r.found("nearby-name", slices.IndexFunc(r.keys.CNANear, func(k CNANearKey) bool {
		return k.FullVendor == vendor && k.Fragment == fragment
	}))
	r.data.CNANear[i].Rows = append(r.data.CNANear[i].Rows, rows...)
	return r
}

// cnaStored adds row at every CNA name key and nearby-name key the store would
// return it from, for a CVE with no cve_cpe_matches row: an exact name key whose
// vendor and product equal the row's in lower case, a prefix key whose product
// starts the row's, and a nearby-name key whose vendor equals the row's and whose
// fragment the row's product contains.
func (r *testRows) cnaStored(row CNARow) *testRows {
	vendor, product := strings.ToLower(row.Vendor), strings.ToLower(row.Product)
	for i, k := range r.keys.CNANames {
		if k.FullVendor == vendor && (k.FullProduct == product || k.FullProduct == "" && strings.HasPrefix(product, k.Lo)) {
			r.data.CNANames[i].Rows = append(r.data.CNANames[i].Rows, row)
		}
	}
	for i, k := range r.keys.CNANear {
		if k.FullVendor == vendor && strings.Contains(product, k.Fragment) {
			near := nearAt(row.CVEID, row.Vendor, row.Product)
			near.Status = row.Status
			r.data.CNANear[i].Rows = append(r.data.CNANear[i].Rows, near)
		}
	}
	return r
}

// nearStored adds row at every nearby-name key the store would return it from,
// for a CVE whose cve_cpe_matches rows are nvdCPEs: a key whose vendor equals
// the row's in lower case, whose fragment the row's product contains, and none
// of whose vendor ranges holds one of nvdCPEs.
func (r *testRows) nearStored(row CNANearRow, nvdCPEs ...string) *testRows {
	vendor, product := strings.ToLower(row.Vendor), strings.ToLower(row.Product)
	for i, k := range r.keys.CNANear {
		analysed := slices.ContainsFunc(k.VendorRanges, func(vr CPEKey) bool {
			return slices.ContainsFunc(nvdCPEs, func(cpe string) bool { return cpe >= vr.Lo && cpe < vr.Hi })
		})
		if k.FullVendor == vendor && strings.Contains(product, k.Fragment) && !analysed {
			r.data.CNANear[i].Rows = append(r.data.CNANear[i].Rows, row)
		}
	}
	return r
}

func pkgAt(cve, introduced, fixed string) PackageRow {
	return PackageRow{CVEID: cve, RangeType: "ECOSYSTEM", Introduced: introduced, Fixed: fixed}
}

// For npm version 1.5.0: a row that contains it, one that excludes it, and one
// that cannot be compared (no introduced bound).
func affectedPkg(cve string) PackageRow { return pkgAt(cve, "1.0.0", "2.0.0") }
func clearPkg(cve string) PackageRow    { return pkgAt(cve, "2.0.0", "3.0.0") }
func cannotPkg(cve string) PackageRow   { return pkgAt(cve, "", "3.0.0") }

func withStatus(row PackageRow, status string) PackageRow {
	row.Status = status
	return row
}

func cpeAt(cve, cpe, startIncluding, endExcluding string) CPERow {
	return CPERow{CVEID: cve, CPE: cpe, VersionStartIncluding: startIncluding, VersionEndExcluding: endExcluding}
}

func cnaAt(cve, vendor, product string, versions ...CNAVersion) CNARow {
	return CNARow{CVEID: cve, Vendor: vendor, Product: product, Versions: versions}
}

func nearAt(cve, vendor, product string) CNANearRow {
	return CNANearRow{CVEID: cve, Vendor: vendor, Product: product}
}

func feedsWith(complete bool) map[string]FeedStatus {
	return map[string]FeedStatus{
		"ghsa": {Name: "ghsa", Complete: complete},
		"osv":  {Name: "osv", Complete: complete},
		"nvd":  {Name: "nvd", Complete: complete},
	}
}

func run(t *testing.T, items []Item, r *testRows) Results {
	t.Helper()
	return runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, DefaultLimits)
}

func runWith(t *testing.T, m *workMeter, items []Item, r *testRows, feeds map[string]FeedStatus,
	enrichment map[string]CVEEnrichment, limits Limits) Results {
	t.Helper()
	got, err := evaluateItems(m, items, r.data, feeds, enrichment, limits)
	if err != nil {
		t.Fatalf("evaluateItems: %v", err)
	}
	if len(got.Results) != len(items) {
		t.Fatalf("results = %d, want one per item (%d)", len(got.Results), len(items))
	}
	return got
}

// summary is the part of an item result the status tests compare. reason is
// "null" when the item's reason is null.
type summary struct {
	status   string
	reason   string
	warnings []string
	counts   Counts
	listed   []string
}

func summarize(t *testing.T, r ItemResult) summary {
	t.Helper()
	s := summary{status: r.Status, reason: "null", warnings: r.Warnings, counts: r.Counts}
	if r.Reason != nil {
		s.reason = string(*r.Reason)
	}
	if r.Warnings == nil || r.Advisories == nil {
		t.Errorf("warnings %v and advisories %v must be non-nil so the JSON holds []", r.Warnings, r.Advisories)
	}
	for _, a := range r.Advisories {
		s.listed = append(s.listed, a.AdvisoryID)
	}
	return s
}

const (
	cveA = "CVE-2026-0001"
	cveB = "CVE-2026-0002"
	cveC = "CVE-2026-0003"
	cveD = "CVE-2026-0004"
	cveE = "CVE-2026-0005"
)

var (
	npmItem    = RawItem{Ecosystem: "npm", Name: "pkg", Version: "1.5.0"}
	widgetItem = RawItem{CPE: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", Version: "1.5.0"}
	nodeItem   = RawItem{CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "24.22.1"}
	ubuntuItem = RawItem{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5", Version: "8.5.4-0ubuntu1.4"}
	widgetCPE  = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"
	nodeCPE    = "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*"
)

// TestEvaluateItemStatus walks design section 4.7's table in order. Each case
// sets up the conditions of its row and of a later row, to show the earlier
// row wins.
func TestEvaluateItemStatus(t *testing.T) {
	t.Parallel()
	none := []string{}
	tests := []struct {
		name   string
		raw    RawItem
		rows   func(r *testRows)
		feeds  map[string]FeedStatus
		limits Limits
		want   summary
	}{
		{
			name: "invalid input", raw: RawItem{Ecosystem: "npm"},
			want: summary{status: "invalid", reason: "null", warnings: none},
		},
		{
			name: "over the item row limit beats an affected advisory", raw: npmItem,
			rows:   func(r *testRows) { r.packages("npm", "pkg", affectedPkg(cveA), affectedPkg(cveB), affectedPkg(cveC)) },
			limits: Limits{ItemRows: 2, AdvisoryRanges: 1000},
			want:   summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "at the item row limit is evaluated", raw: npmItem,
			rows:   func(r *testRows) { r.packages("npm", "pkg", affectedPkg(cveA), affectedPkg(cveB)) },
			limits: Limits{ItemRows: 2, AdvisoryRanges: 1000},
			want: summary{status: "affected", reason: "null", warnings: none,
				counts: Counts{Affected: 2}, listed: []string{cveA, cveB}},
		},
		{
			name: "the item row limit counts every source and name variant, including nearby names", raw: nodeItem,
			rows: func(r *testRows) {
				r.cpes("nodejs", "node.js", cpeAt(cveA, nodeCPE, "23.0.0", "24.22.1")).
					cnaName("nodejs", "node", false, cnaAt(cveB, "nodejs", "node")).
					near("nodejs", nearAt(cveB, "nodejs", "node"))
			},
			limits: Limits{ItemRows: 2, AdvisoryRanges: 1000},
			want:   summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "the item row limit counts CNA package-key rows", raw: npmItem,
			rows: func(r *testRows) {
				r.packages("npm", "pkg", affectedPkg(cveA)).cnaPackage("npm/pkg", cnaAt(cveB, "", ""), cnaAt(cveC, "", ""))
			},
			limits: Limits{ItemRows: 2, AdvisoryRanges: 1000},
			want:   summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "a key at its own limit beats an affected advisory", raw: npmItem,
			rows: func(r *testRows) { r.packages("npm", "pkg", affectedPkg(cveA)).overflowPackages("npm", "pkg") },
			want: summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "a CPE key at its own limit", raw: nodeItem,
			rows: func(r *testRows) {
				r.cpes("nodejs", "node.js", cpeAt(cveA, nodeCPE, "24.0.0", "")).overflowCPEs("nodejs", "node.js")
			},
			want: summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "a CNA name key at its own limit", raw: nodeItem,
			rows: func(r *testRows) {
				r.cpes("nodejs", "node.js", cpeAt(cveA, nodeCPE, "24.0.0", "")).overflowCNAName("nodejs", "node", false)
			},
			want: summary{status: "cannot_evaluate", reason: "too_many_candidates", warnings: none},
		},
		{
			name: "affected beats an advisory that cannot be evaluated, on incomplete data", raw: npmItem,
			rows:  func(r *testRows) { r.packages("npm", "pkg", cannotPkg(cveA), affectedPkg(cveB)) },
			feeds: feedsWith(false),
			want: summary{status: "affected", reason: "null", warnings: none,
				counts: Counts{Affected: 1, CannotEvaluate: 1}, listed: []string{cveB, cveA}},
		},
		{
			name: "an advisory that cannot be evaluated beats data_incomplete, with a null item reason", raw: npmItem,
			rows:  func(r *testRows) { r.packages("npm", "pkg", cannotPkg(cveA), clearPkg(cveB)) },
			feeds: feedsWith(false),
			want: summary{status: "cannot_evaluate", reason: "null", warnings: none,
				counts: Counts{CannotEvaluate: 1, NotAffected: 1}, listed: []string{cveA}},
		},
		{
			name: "data_incomplete beats cna_product_not_mapped", raw: widgetItem,
			rows:  func(r *testRows) { r.cpes("acme", "widget", cpeAt(cveA, widgetCPE, "2.0.0", "3.0.0")) },
			feeds: feedsWith(false),
			want: summary{status: "cannot_evaluate", reason: "data_incomplete", warnings: none,
				counts: Counts{NotAffected: 1}},
		},
		{
			name: "data_incomplete for a package item", raw: npmItem,
			rows:  func(r *testRows) { r.packages("npm", "pkg", clearPkg(cveA)) },
			feeds: feedsWith(false),
			want: summary{status: "cannot_evaluate", reason: "data_incomplete", warnings: none,
				counts: Counts{NotAffected: 1}},
		},
		{
			name: "data_incomplete for a distro package item", raw: ubuntuItem,
			rows:  func(r *testRows) { r.packages("Ubuntu:26.04:LTS", "php8.5", pkgAt(cveA, "0", "8.5.4-0ubuntu1.3")) },
			feeds: feedsWith(false),
			want: summary{status: "cannot_evaluate", reason: "data_incomplete", warnings: none,
				counts: Counts{NotAffected: 1}},
		},
		{
			name: "cna_product_not_mapped when otherwise clean", raw: widgetItem,
			rows: func(r *testRows) { r.cpes("acme", "widget", cpeAt(cveA, widgetCPE, "2.0.0", "3.0.0")) },
			want: summary{status: "cannot_evaluate", reason: "cna_product_not_mapped", warnings: none,
				counts: Counts{NotAffected: 1}},
		},
		{
			name: "a CPE in the name table is mapped", raw: nodeItem,
			rows: func(r *testRows) { r.cpes("nodejs", "node.js", cpeAt(cveA, nodeCPE, "23.0.0", "24.22.1")) },
			want: summary{status: "not_affected", reason: "null", warnings: none, counts: Counts{NotAffected: 1}},
		},
		{
			name: "a CPE with a CNA row under its own name is mapped, even a retracted one", raw: widgetItem,
			rows: func(r *testRows) {
				row := cnaAt(cveB, "acme", "widget")
				row.Status = "Rejected"
				r.cpes("acme", "widget", cpeAt(cveA, widgetCPE, "2.0.0", "3.0.0")).cnaName("acme", "widget", false, row)
			},
			want: summary{status: "not_affected", reason: "null", warnings: none,
				counts: Counts{NotAffected: 1, Retracted: 1}},
		},
		{
			name: "all advisories not affected", raw: npmItem,
			rows: func(r *testRows) { r.packages("npm", "pkg", clearPkg(cveA), clearPkg(cveB)) },
			want: summary{status: "not_affected", reason: "null", warnings: none, counts: Counts{NotAffected: 2}},
		},
		{
			name: "a distro package with advisories, all not affected", raw: ubuntuItem,
			rows: func(r *testRows) { r.packages("Ubuntu:26.04:LTS", "php8.5", pkgAt(cveA, "0", "8.5.4-0ubuntu1.3")) },
			want: summary{status: "not_affected", reason: "null", warnings: none, counts: Counts{NotAffected: 1}},
		},
		{
			name: "a distro package with no rows", raw: ubuntuItem,
			want: summary{status: "cannot_evaluate", reason: "distro_package_not_found", warnings: none},
		},
		{
			name: "a distro package whose only advisories are retracted has rows, so no advisory is found", raw: ubuntuItem,
			rows: func(r *testRows) {
				r.packages("Ubuntu:26.04:LTS", "php8.5", withStatus(pkgAt(cveA, "0", "8.5.4-0ubuntu1.5"), "REJECTED"))
			},
			want: summary{status: "no_advisory_found", reason: "null", warnings: none, counts: Counts{Retracted: 1}},
		},
		{
			name: "a package with no rows", raw: npmItem,
			want: summary{status: "no_advisory_found", reason: "null", warnings: none},
		},
		{
			name: "a package with no rows on incomplete data", raw: npmItem, feeds: feedsWith(false),
			want: summary{status: "no_advisory_found", reason: "null", warnings: none},
		},
		{
			name: "a CPE with no CNA name and no rows carries a warning", raw: widgetItem,
			want: summary{status: "no_advisory_found", reason: "null", warnings: []string{"cna_product_not_mapped"}},
		},
		{
			name: "a mapped CPE with no rows carries no warning", raw: nodeItem,
			want: summary{status: "no_advisory_found", reason: "null", warnings: none},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(tt.raw)
			r := rowsFor(t, items)
			if tt.rows != nil {
				tt.rows(r)
			}
			feeds, limits := tt.feeds, tt.limits
			if feeds == nil {
				feeds = feedsWith(true)
			}
			if limits == (Limits{}) {
				limits = DefaultLimits
			}
			got := runWith(t, newWorkMeter(context.Background()), items, r, feeds, nil, limits)
			if s := summarize(t, got.Results[0]); !reflect.DeepEqual(s, tt.want) {
				t.Errorf("item = %+v\nwant   %+v", s, tt.want)
			}
		})
	}
}

// TestEvaluateRetracted checks design section 8: an advisory whose CVE is
// rejected or withdrawn, in any case and from any of its rows, is counted and
// not evaluated or listed.
func TestEvaluateRetracted(t *testing.T) {
	t.Parallel()
	items := parseItems(npmItem)
	cna := cnaAt(cveD, "", "", CNAVersion{Version: "1.0.0", LessThan: "2.0.0", Status: "affected", VersionType: "semver"})
	cna.Status = "withdrawn"
	r := rowsFor(t, items).
		packages("npm", "pkg",
			affectedPkg(cveA),
			withStatus(affectedPkg(cveB), "Rejected"),
			withStatus(clearPkg(cveC), "WITHDRAWN"),
			withStatus(affectedPkg(cveE), "rejected"), withStatus(cannotPkg(cveE), "rejected"),
		).
		cnaPackage("npm/pkg", cna)
	got := summarize(t, run(t, items, r).Results[0])
	want := summary{status: "affected", reason: "null", warnings: []string{},
		counts: Counts{Affected: 1, Retracted: 4}, listed: []string{cveA}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("item = %+v\nwant   %+v", got, want)
	}
}

func TestIsRetracted(t *testing.T) {
	t.Parallel()
	for status, want := range map[string]bool{
		"": false, "PUBLISHED": false, "rejected": true, "REJECTED": true, "Withdrawn": true, "reserved": false,
	} {
		if got := isRetracted(status); got != want {
			t.Errorf("isRetracted(%q) = %v, want %v", status, got, want)
		}
	}
}

// advisoryReasons maps each listed advisory to its verdict and reason.
func advisoryReasons(r ItemResult) map[string]string {
	out := map[string]string{}
	for _, a := range r.Advisories {
		reason := "null"
		if a.Reason != nil {
			reason = string(*a.Reason)
		}
		out[a.AdvisoryID] = a.Verdict + "/" + reason
	}
	return out
}

// TestEvaluateTooManyRanges checks the 1,000-range limit per advisory: package
// or CPE rows plus CNARangeCount of the CNA rows, decided before any reading.
func TestEvaluateTooManyRanges(t *testing.T) {
	t.Parallel()

	t.Run("package and CNA ranges are counted together", func(t *testing.T) {
		t.Parallel()
		items := parseItems(npmItem)
		cnaClear := func(cve string) CNARow {
			return cnaAt(cve, "", "", CNAVersion{Version: "3.0.0", LessThan: "4.0.0", Status: "affected", VersionType: "semver"})
		}
		r := rowsFor(t, items).
			packages("npm", "pkg",
				affectedPkg(cveA), affectedPkg(cveA), affectedPkg(cveA), affectedPkg(cveA), // 4 ranges
				affectedPkg(cveB), affectedPkg(cveB), affectedPkg(cveB), // 3 ranges
				clearPkg(cveC), clearPkg(cveC), // 2 + 2 ranges
				clearPkg(cveD), // 1 + 2 ranges
			).
			cnaPackage("npm/pkg", cnaClear(cveC), cnaClear(cveD))
		res := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, Limits{ItemRows: 50000, AdvisoryRanges: 3})
		got := res.Results[0]
		want := map[string]string{
			cveA: "cannot_evaluate/too_many_ranges",
			cveB: "affected/null",
			cveC: "cannot_evaluate/too_many_ranges",
		}
		if !reflect.DeepEqual(advisoryReasons(got), want) {
			t.Errorf("advisories = %v, want %v", advisoryReasons(got), want)
		}
		if wantCounts := (Counts{Affected: 1, CannotEvaluate: 2, NotAffected: 1}); got.Counts != wantCounts {
			t.Errorf("counts = %+v, want %+v", got.Counts, wantCounts)
		}
	})

	t.Run("CPE ranges are counted", func(t *testing.T) {
		t.Parallel()
		items := parseItems(nodeItem)
		row := cpeAt(cveA, nodeCPE, "24.0.0", "")
		r := rowsFor(t, items).cpes("nodejs", "node.js", row, row, row, row).cpes("nodejs", "node.js", cpeAt(cveB, nodeCPE, "24.0.0", ""))
		res := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, Limits{ItemRows: 50000, AdvisoryRanges: 3})
		want := map[string]string{cveA: "cannot_evaluate/too_many_ranges", cveB: "affected/null"}
		if got := advisoryReasons(res.Results[0]); !reflect.DeepEqual(got, want) {
			t.Errorf("advisories = %v, want %v", got, want)
		}
	})

	t.Run("a CNA row with 10,000 changes is refused before any comparison", func(t *testing.T) {
		t.Parallel()
		items := parseItems(nodeItem)
		r := rowsFor(t, items).cnaName("nodejs", "node", false, cnaAt(cveA, "nodejs", "node", manyChanges(10000)))
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }
		got := runWith(t, m, items, r, feedsWith(true), nil, DefaultLimits).Results[0]
		if ticks != 0 {
			t.Errorf("ticks = %d, want 0: the range limit is decided before reading", ticks)
		}
		if want := map[string]string{cveA: "cannot_evaluate/too_many_ranges"}; !reflect.DeepEqual(advisoryReasons(got), want) {
			t.Errorf("advisories = %v, want %v", advisoryReasons(got), want)
		}
		if got.Status != StatusCannotEvaluate || got.Reason != nil {
			t.Errorf("item status = %s, reason %v; want cannot_evaluate with a null reason", got.Status, got.Reason)
		}
	})
}

// TestEvaluateListing checks that Not-affected advisories are counted and not
// listed, and that at most 100 are listed, Affected first, then KEV, then score.
func TestEvaluateListing(t *testing.T) {
	t.Parallel()
	advisoryRows := func(affected int) []PackageRow {
		rows := []PackageRow{cannotPkg("CVE-2026-0999"), clearPkg("CVE-2026-2000"), clearPkg("CVE-2026-2001")}
		for i := range affected {
			rows = append(rows, affectedPkg(fmt.Sprintf("CVE-2026-1%03d", i)))
		}
		return rows
	}
	enrichment := map[string]CVEEnrichment{
		"CVE-2026-1102": {InCISAKEV: true},
		"CVE-2026-1050": {CVSSv3Score: ptr(9.8)},
		"CVE-2026-0999": {InCISAKEV: true, CVSSv3Score: ptr(10.0)},
	}

	t.Run("over 100 listed advisories are truncated", func(t *testing.T) {
		t.Parallel()
		items := parseItems(npmItem)
		r := rowsFor(t, items).packages("npm", "pkg", advisoryRows(103)...)
		got := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), enrichment, DefaultLimits).Results[0]
		if len(got.Advisories) != 100 || !got.AdvisoriesTruncated {
			t.Fatalf("listed %d, truncated %v; want 100, true", len(got.Advisories), got.AdvisoriesTruncated)
		}
		if want := (Counts{Affected: 103, CannotEvaluate: 1, NotAffected: 2}); got.Counts != want {
			t.Errorf("counts = %+v, want %+v", got.Counts, want)
		}
		if first := got.Advisories[0].AdvisoryID; first != "CVE-2026-1102" {
			t.Errorf("first listed = %s, want the KEV advisory CVE-2026-1102", first)
		}
		if second := got.Advisories[1].AdvisoryID; second != "CVE-2026-1050" {
			t.Errorf("second listed = %s, want the highest-scored advisory CVE-2026-1050", second)
		}
		for _, a := range got.Advisories {
			if a.Verdict != VerdictAffected {
				t.Errorf("listed %s (%s) while Affected advisories were cut", a.AdvisoryID, a.Verdict)
			}
		}
	})

	t.Run("exactly 100 listed advisories are not truncated", func(t *testing.T) {
		t.Parallel()
		items := parseItems(npmItem)
		r := rowsFor(t, items).packages("npm", "pkg", advisoryRows(99)...)
		got := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), enrichment, DefaultLimits).Results[0]
		if len(got.Advisories) != 100 || got.AdvisoriesTruncated {
			t.Fatalf("listed %d, truncated %v; want 100, false", len(got.Advisories), got.AdvisoriesTruncated)
		}
		if last := got.Advisories[99].AdvisoryID; last != "CVE-2026-0999" {
			t.Errorf("last listed = %s, want the advisory that cannot be evaluated, CVE-2026-0999", last)
		}
	})
}

func TestEvaluateMatchedRangesCap(t *testing.T) {
	t.Parallel()
	for _, n := range []int{20, 25} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			t.Parallel()
			items := parseItems(npmItem)
			var rows []PackageRow
			for i := range n {
				rows = append(rows, pkgAt(cveA, fmt.Sprintf("1.0.%d", i), "2.0.0"))
			}
			got := run(t, items, rowsFor(t, items).packages("npm", "pkg", rows...)).Results[0].Advisories[0]
			if len(got.MatchedRanges) != min(n, 20) || got.MatchedRangesTotal != n {
				t.Errorf("matched_ranges = %d, total %d; want %d, %d", len(got.MatchedRanges), got.MatchedRangesTotal, min(n, 20), n)
			}
		})
	}
}

// TestEvaluateAdvisoryFields checks a listed advisory's fields: severity and
// CVSS from its own row, KEV and EPSS from its cve_ids rows (null when it has
// none), and the fix only for an Affected advisory.
func TestEvaluateAdvisoryFields(t *testing.T) {
	t.Parallel()
	items := parseItems(ubuntuItem, npmItem)
	r := rowsFor(t, items).
		packages("Ubuntu:26.04:LTS", "php8.5",
			pkgAt("UBUNTU-CVE-2026-109618", "0", "8.5.4-0ubuntu1.5"),
			pkgAt("USN-8948-1", "0", "8.5.4-0ubuntu1.5"),
		).
		packages("npm", "pkg", cannotPkg(cveA))
	enrichment := map[string]CVEEnrichment{
		"UBUNTU-CVE-2026-109618": {Severity: ptr("medium"), CVSSv3Score: ptr(5.3)},
		"CVE-2026-109618":        {Severity: ptr("HIGH"), CVSSv3Score: ptr(7.5), InCISAKEV: true, EPSSScore: ptr(0.4)},
		"USN-8948-1":             {Severity: ptr("low")},
		cveA:                     {Severity: ptr("CRITICAL"), CVSSv3Score: ptr(9.1), EPSSScore: ptr(0.3)},
	}
	got := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), enrichment, DefaultLimits)
	fix := "8.5.4-0ubuntu1.5"
	wantDistro := []Advisory{
		{
			AdvisoryID: "UBUNTU-CVE-2026-109618", CVEIDs: []string{"CVE-2026-109618"}, Verdict: VerdictAffected,
			FixedVersion: &fix, FixMajor: ptr("same"),
			MatchedRanges:      []MatchedRange{{Evidence: "package_range", Introduced: "0", Fixed: fix}},
			MatchedRangesTotal: 1, Severity: ptr("medium"), CVSSv3Score: ptr(5.3), EPSSScore: ptr(0.4), InCISAKEV: ptr(true),
		},
		{
			AdvisoryID: "USN-8948-1", CVEIDs: []string{}, Verdict: VerdictAffected,
			FixedVersion: &fix, FixMajor: ptr("same"),
			MatchedRanges:      []MatchedRange{{Evidence: "package_range", Introduced: "0", Fixed: fix}},
			MatchedRangesTotal: 1, Severity: ptr("low"),
		},
	}
	if !reflect.DeepEqual(got.Results[0].Advisories, wantDistro) {
		t.Errorf("distro advisories =\n%s\nwant\n%s", jsonOf(t, got.Results[0].Advisories), jsonOf(t, wantDistro))
	}
	wantCannot := []Advisory{{
		AdvisoryID: cveA, CVEIDs: []string{cveA}, Verdict: VerdictCannotEvaluate, Reason: ptr(ReasonInvalidRange),
		MatchedRanges: []MatchedRange{}, Severity: ptr("CRITICAL"), CVSSv3Score: ptr(9.1), EPSSScore: ptr(0.3), InCISAKEV: ptr(false),
	}}
	if !reflect.DeepEqual(got.Results[1].Advisories, wantCannot) {
		t.Errorf("advisory that cannot be evaluated =\n%s\nwant\n%s", jsonOf(t, got.Results[1].Advisories), jsonOf(t, wantCannot))
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// TestEvaluateCNAPackageRows checks design section 4.6: a non-distro package
// item reads CNA rows by package key, and the fix is checked against them.
func TestEvaluateCNAPackageRows(t *testing.T) {
	t.Parallel()
	fastify := RawItem{Ecosystem: "npm", Name: "fastify", Version: "5.12.3"}
	semver := func(from, below string) CNAVersion {
		return CNAVersion{Version: from, LessThan: below, Status: "affected", VersionType: "semver"}
	}
	tests := []struct {
		name    string
		pkgRows []PackageRow
		cnaRows []CNARow
		want    string
		fix     string
	}{
		{
			name: "CNA alone reports Affected with its fix", cnaRows: []CNARow{cnaAt(cveA, "", "", semver("5.0.0", "5.12.6"))},
			want: "affected/null", fix: "5.12.6",
		},
		{
			name:    "a package fix the CNA entry still reports Affected is passed over",
			pkgRows: []PackageRow{pkgAt(cveA, "5.0.0", "5.12.4")}, cnaRows: []CNARow{cnaAt(cveA, "", "", semver("5.0.0", "5.12.6"))},
			want: "affected/null", fix: "5.12.6",
		},
		{
			name: "CNA alone never clears", cnaRows: []CNARow{cnaAt(cveA, "", "", semver("6.0.0", "6.1.0"))},
			want: "cannot_evaluate/cna_cannot_clear",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(fastify)
			r := rowsFor(t, items).packages("npm", "fastify", tt.pkgRows...).cnaPackage("npm/fastify", tt.cnaRows...)
			got := run(t, items, r).Results[0]
			if want := map[string]string{cveA: tt.want}; !reflect.DeepEqual(advisoryReasons(got), want) {
				t.Fatalf("advisories = %v, want %v", advisoryReasons(got), want)
			}
			if fixed := deref(got.Advisories[0].FixedVersion); tt.fix != "" && fixed != tt.fix || tt.fix == "" && fixed != nil {
				t.Errorf("fixed_version = %v, want %q", fixed, tt.fix)
			}
		})
	}
}

// TestEvaluateCNANamesDeduplicated checks that a stored row found through two
// CNA name keys (exact ".net core" and prefix ".net ") is read once: one matched
// range, and its ranges counted once toward the limit.
func TestEvaluateCNANamesDeduplicated(t *testing.T) {
	t.Parallel()
	items := parseItems(RawItem{CPE: "cpe:2.3:a:microsoft:.net_core:9.0.1:*:*:*:*:*:*:*"})
	row := cnaAt(cveA, "Microsoft", ".NET Core", CNAVersion{Version: "9.0.0", LessThan: "9.0.5", Status: "affected", VersionType: "custom"})
	r := rowsFor(t, items).cnaName("microsoft", ".net core", false, row).cnaName("microsoft", ".net ", true, row)
	got := runWith(t, newWorkMeter(context.Background()), items, r, feedsWith(true), nil, Limits{ItemRows: 50000, AdvisoryRanges: 3})
	a := got.Results[0].Advisories
	if len(a) != 1 || a[0].Verdict != VerdictAffected || a[0].MatchedRangesTotal != 1 || deref(a[0].FixedVersion) != "9.0.5" {
		t.Errorf("advisories = %s, want one Affected advisory with one matched range and fix 9.0.5", jsonOf(t, a))
	}
}

// TestEvaluateOtherCPESpellings checks that a CPE item reads the NVD rows of the
// other CPE spellings its name table row lists: older nginx CVEs are under
// nginx:nginx only, and a f5:nginx item must not answer not_affected for them.
func TestEvaluateOtherCPESpellings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		item            string
		vendor, product string // where the advisory's NVD rows are stored
		start, end      string
	}{
		{name: "f5:nginx reads nginx:nginx", item: "cpe:2.3:a:f5:nginx:1.13.0:*:*:*:*:*:*:*",
			vendor: "nginx", product: "nginx", start: "0.5.6", end: "1.13.3"},
		{name: "nginx:nginx reads f5:nginx", item: "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*",
			vendor: "f5", product: "nginx", start: "1.25.0", end: "1.25.4"},
		{name: "microsoft:.net reads microsoft:.net_core", item: "cpe:2.3:a:microsoft:.net:3.1.0:*:*:*:*:*:*:*",
			vendor: "microsoft", product: ".net_core", start: "3.1.0", end: "3.1.32"},
		{name: "microsoft:.net_core reads microsoft:.net", item: "cpe:2.3:a:microsoft:.net_core:8.0.1:*:*:*:*:*:*:*",
			vendor: "microsoft", product: ".net", start: "8.0.0", end: "8.0.11"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(RawItem{CPE: tt.item})
			stored := "cpe:2.3:a:" + tt.vendor + ":" + tt.product + ":*:*:*:*:*:*:*:*"
			r := rowsFor(t, items).cpes(tt.vendor, tt.product, cpeAt(cveA, stored, tt.start, tt.end))
			got := run(t, items, r).Results[0]
			if got.Status != StatusAffected || got.Counts != (Counts{Affected: 1}) {
				t.Errorf("status = %s, counts %+v; want affected by %s; advisories %s",
					got.Status, got.Counts, cveA, jsonOf(t, got.Advisories))
			}
		})
	}
}

// TestEvaluateNearbyLiftEverySpelling checks that both nginx spellings, which
// read each other's NVD rows, also share the nearby-name lift: a CVE that NVD
// analysed under either spelling's vendor holds back neither item, so the two
// items in one request answer alike.
func TestEvaluateNearbyLiftEverySpelling(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		vendor, product string // where the advisory's NVD row is stored
	}{
		{name: "NVD row under f5:nginx", vendor: "f5", product: "nginx"},
		{name: "NVD row under nginx:nginx", vendor: "nginx", product: "nginx"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(
				RawItem{CPE: "cpe:2.3:a:f5:nginx:1.20.0:*:*:*:*:*:*:*"},
				RawItem{CPE: "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"},
			)
			stored := "cpe:2.3:a:" + tt.vendor + ":" + tt.product + ":*:*:*:*:*:*:*:*"
			r := rowsFor(t, items).
				cpes(tt.vendor, tt.product, cpeAt(cveA, stored, "1.25.0", "1.25.4")).
				cnaName("f5", "nginx open source", false, cnaAt(cveA, "F5", "NGINX Open Source",
					CNAVersion{Version: "1.25.0", LessThan: "1.25.4", Status: "affected", VersionType: "semver"})).
				nearStored(nearAt(cveA, "F5", "NGINX Open Source"), stored).
				nearStored(nearAt(cveA, "F5", "NGINX Plus"), stored)
			got := run(t, items, r).Results
			for i, res := range got {
				if res.Status != StatusNotAffected || res.Counts != (Counts{NotAffected: 1}) {
					t.Errorf("item %d: status = %s, counts %+v, advisories %v; want not_affected by %s",
						i, res.Status, res.Counts, advisoryReasons(res), cveA)
				}
			}
		})
	}
}

// TestEvaluateCNAUnderscoreKept checks that a CPE product holding "_" finds CNA
// rows that keep the "_" as well as rows that write a space: a CVE known only
// through a CNA row acme / foo_bar, or only through a nearby row whose product
// holds foo_bar, keeps the item from not_affected.
func TestEvaluateCNAUnderscoreKept(t *testing.T) {
	t.Parallel()
	item := RawItem{CPE: "cpe:2.3:a:acme:foo_bar:*:*:*:*:*:*:*:*", Version: "1.5.0"}
	stored := "cpe:2.3:a:acme:foo_bar:*:*:*:*:*:*:*:*"
	// cveA is analysed by NVD and clear; cveC's CNA row under the spaced name
	// shows the product is mapped.
	base := func(r *testRows) *testRows {
		retracted := cnaAt(cveC, "Acme", "Foo Bar")
		retracted.Status = "REJECTED"
		return r.cpes("acme", "foo_bar", cpeAt(cveA, stored, "2.0.0", "3.0.0")).cnaName("acme", "foo bar", false, retracted)
	}
	tests := []struct {
		name string
		rows func(r *testRows)
		want map[string]string
	}{
		{
			name: "a CNA row that keeps the underscore",
			rows: func(r *testRows) {
				base(r).cnaName("acme", "foo_bar", false, cnaAt(cveB, "acme", "foo_bar",
					CNAVersion{Version: "2.0.0", LessThan: "3.0.0", Status: "affected", VersionType: "semver"}))
			},
			want: map[string]string{cveB: "cannot_evaluate/cna_cannot_clear"},
		},
		{
			name: "a nearby row that keeps the underscore",
			rows: func(r *testRows) { base(r).nearFragment("acme", "foo_bar", nearAt(cveB, "acme", "foo_bar plugin")) },
			want: map[string]string{cveB: "cannot_evaluate/cna_name_uncertain"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(item)
			r := rowsFor(t, items)
			tt.rows(r)
			got := run(t, items, r).Results[0]
			if got.Status != StatusCannotEvaluate || !reflect.DeepEqual(advisoryReasons(got), tt.want) {
				t.Errorf("status = %s, advisories %v; want cannot_evaluate with %v", got.Status, advisoryReasons(got), tt.want)
			}
		})
	}
}

// TestEvaluateCNAMixedUnderscores checks that a CPE whose vendor and product
// both hold "_" finds a CNA row that reads one "_" as a space and keeps the
// other: a CVE known only through such a row, and Affected by it, keeps the item
// from not_affected.
func TestEvaluateCNAMixedUnderscores(t *testing.T) {
	t.Parallel()
	stored := "cpe:2.3:a:acme_corp:foo_bar:*:*:*:*:*:*:*:*"
	for _, name := range []struct{ vendor, product string }{{"Acme Corp", "foo_bar"}, {"acme_corp", "Foo Bar"}} {
		t.Run(name.vendor+" / "+name.product, func(t *testing.T) {
			t.Parallel()
			items := parseItems(RawItem{CPE: "cpe:2.3:a:acme_corp:foo_bar:1.5.0:*:*:*:*:*:*:*"})
			// cveA is analysed by NVD and clear; cveC's CNA row under the spaced
			// name shows the product is mapped.
			retracted := cnaAt(cveC, "Acme Corp", "Foo Bar")
			retracted.Status = "REJECTED"
			r := rowsFor(t, items).
				cpes("acme_corp", "foo_bar", cpeAt(cveA, stored, "2.0.0", "3.0.0")).
				cnaName("acme corp", "foo bar", false, retracted).
				cnaStored(cnaAt(cveB, name.vendor, name.product,
					CNAVersion{Version: "1.0.0", LessThan: "2.0.0", Status: "affected", VersionType: "semver"}))
			got := run(t, items, r).Results[0]
			want := map[string]string{cveB: "affected/null"}
			if got.Status != StatusAffected || !reflect.DeepEqual(advisoryReasons(got), want) {
				t.Errorf("status = %s, counts %+v, advisories %v; want affected with %v",
					got.Status, got.Counts, advisoryReasons(got), want)
			}
		})
	}
}

// TestEvaluateCNACopiesDifferingInVersions checks that two stored CNA rows on
// one CVE that differ only in their versions are both read: the second copy
// reports 24.22.1 Affected where NVD's range does not.
func TestEvaluateCNACopiesDifferingInVersions(t *testing.T) {
	t.Parallel()
	items := parseItems(nodeItem)
	affected := func(from, below string) CNAVersion {
		return CNAVersion{Version: from, LessThan: below, Status: "affected"}
	}
	r := rowsFor(t, items).
		cpes("nodejs", "node.js", cpeAt(cveA, nodeCPE, "23.0.0", "24.22.1")).
		cnaName("nodejs", "node", false,
			cnaAt(cveA, "nodejs", "node", affected("20.0.0", "20.5.0")),
			cnaAt(cveA, "nodejs", "node", affected("24.0.0", "24.23.0")),
		)
	got := run(t, items, r).Results[0]
	if got.Status != StatusAffected {
		t.Errorf("status = %s, want affected; advisories %s", got.Status, jsonOf(t, got.Advisories))
	}
}

// TestEvaluateItemsDifferingInOneField checks that items differing only in CPE
// part, only in product, or only in ecosystem are each evaluated, not answered
// from another's evaluation.
func TestEvaluateItemsDifferingInOneField(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raws []RawItem
		rows func(r *testRows)
	}{
		{
			name: "CPE part",
			raws: []RawItem{widgetItem, {CPE: "cpe:2.3:o:acme:widget:*:*:*:*:*:*:*:*", Version: "1.5.0"}},
			rows: func(r *testRows) { r.cpes("acme", "widget", cpeAt(cveA, widgetCPE, "1.0.0", "2.0.0")) },
		},
		{
			name: "product",
			raws: []RawItem{widgetItem, {CPE: "cpe:2.3:a:acme:gadget:*:*:*:*:*:*:*:*", Version: "1.5.0"}},
			rows: func(r *testRows) { r.cpes("acme", "widget", cpeAt(cveA, widgetCPE, "1.0.0", "2.0.0")) },
		},
		{
			name: "ecosystem",
			raws: []RawItem{npmItem, {Ecosystem: "PyPI", Name: "pkg", Version: "1.5.0"}},
			rows: func(r *testRows) { r.packages("npm", "pkg", affectedPkg(cveA)) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(tt.raws...)
			r := rowsFor(t, items)
			tt.rows(r)
			got := run(t, items, r).Results
			for i, item := range items {
				if !reflect.DeepEqual(got[i].Component, componentOf(item)) {
					t.Errorf("item %d component = %+v, want %+v", i, got[i].Component, componentOf(item))
				}
			}
			if got[0].Status != StatusAffected || got[1].Status != StatusNoAdvisoryFound {
				t.Errorf("statuses = %s, %s; want affected, then no_advisory_found", got[0].Status, got[1].Status)
			}
		})
	}
}

// TestEvaluateCNANameUncertain checks design section 4.5's nearby names, at row
// level: a nearby row that is not one of the item's CNA name rows makes its
// advisory cna_name_uncertain unless the advisory reports Affected.
func TestEvaluateCNANameUncertain(t *testing.T) {
	t.Parallel()
	dotnet := RawItem{CPE: "cpe:2.3:a:microsoft:.net:9.0.20:*:*:*:*:*:*:*"}
	net9 := func(cve, below string) CNARow {
		return cnaAt(cve, "Microsoft", ".NET 9.0", CNAVersion{Version: "9.0.0", LessThan: below, Status: "affected", VersionType: "custom"})
	}
	tests := []struct {
		name  string
		names []CNARow
		near  []CNANearRow
		want  map[string]string
		count Counts
	}{
		{
			// Verify first: filtering nearby rows by CVE alone answers cna_cannot_clear here.
			name:  ".NET 9.0 and Microsoft .NET Runtime on one CVE with no Microsoft CPE row",
			names: []CNARow{net9(cveA, "9.0.15")},
			near:  []CNANearRow{nearAt(cveA, "Microsoft", ".NET 9.0"), nearAt(cveA, "Microsoft", "Microsoft .NET Runtime")},
			want:  map[string]string{cveA: "cannot_evaluate/cna_name_uncertain"},
			count: Counts{CannotEvaluate: 1},
		},
		{
			name:  "a nearby row that is one of the item's own rows is dropped",
			names: []CNARow{net9(cveA, "9.0.15")},
			near:  []CNANearRow{nearAt(cveA, "Microsoft", ".NET 9.0")},
			want:  map[string]string{cveA: "cannot_evaluate/cna_cannot_clear"},
			count: Counts{CannotEvaluate: 1},
		},
		{
			name:  "a CVE known only through a nearby row is an advisory of its own",
			near:  []CNANearRow{nearAt(cveB, "Microsoft", "Microsoft .NET Runtime")},
			want:  map[string]string{cveB: "cannot_evaluate/cna_name_uncertain"},
			count: Counts{CannotEvaluate: 1},
		},
		{
			name:  "an Affected advisory stays Affected",
			names: []CNARow{net9(cveA, "9.0.21")},
			near:  []CNANearRow{nearAt(cveA, "Microsoft", ".NET 9.0"), nearAt(cveA, "Microsoft", "Microsoft .NET Runtime")},
			want:  map[string]string{cveA: "affected/null"},
			count: Counts{Affected: 1},
		},
		{
			name:  "a retracted nearby row is counted as retracted",
			near:  []CNANearRow{{CVEID: cveB, Vendor: "Microsoft", Product: "Microsoft .NET Runtime", Status: "REJECTED"}},
			want:  map[string]string{},
			count: Counts{Retracted: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(dotnet)
			r := rowsFor(t, items).cnaName("microsoft", ".net ", true, tt.names...).near("microsoft", tt.near...)
			got := run(t, items, r).Results[0]
			if !reflect.DeepEqual(advisoryReasons(got), tt.want) {
				t.Errorf("advisories = %v, want %v", advisoryReasons(got), tt.want)
			}
			if got.Counts != tt.count {
				t.Errorf("counts = %+v, want %+v", got.Counts, tt.count)
			}
		})
	}
}

// TestEvaluateFeeds checks design section 5's dependencies: each item's
// data_complete, and the top-level feeds and data_complete over valid items.
func TestEvaluateFeeds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	fresh, stale := now.Add(-time.Hour), now.Add(-8*24*time.Hour)
	osvCursor, _ := json.Marshal(map[string]string{"last_modified": "2026-11-10T11:00:00Z"})
	feeds := FeedStatuses([]FeedRow{
		{Name: "osv", CursorJSON: osvCursor, LastSuccessAt: &fresh},
		{Name: "nvd", CursorJSON: []byte(`{"caught_up":true}`), LastSuccessAt: &stale},
	}, now)
	osv := FeedStatus{Name: "osv", Complete: true, LastSuccessAt: &fresh}
	nvd := FeedStatus{Name: "nvd", LastSuccessAt: &stale}
	ghsa := FeedStatus{Name: "ghsa"}
	tests := []struct {
		name      string
		raws      []RawItem
		feeds     map[string]FeedStatus
		wantItems []bool
		wantFeeds []FeedStatus
		wantAll   bool
	}{
		{"a distro item needs only OSV, so no GHSA cursor is complete", []RawItem{ubuntuItem}, feeds,
			[]bool{true}, []FeedStatus{osv}, true},
		{"another package item needs GHSA, OSV and NVD", []RawItem{npmItem}, feeds,
			[]bool{false}, []FeedStatus{ghsa, nvd, osv}, false},
		{"a CPE item needs NVD, here 8 days stale", []RawItem{widgetItem}, feeds,
			[]bool{false}, []FeedStatus{nvd}, false},
		{"an invalid item depends on no feed", []RawItem{{}, ubuntuItem}, feeds,
			[]bool{false, true}, []FeedStatus{osv}, true},
		{"no valid items", []RawItem{{}}, feeds, []bool{false}, []FeedStatus{}, true},
		{"one incomplete item makes the request incomplete", []RawItem{ubuntuItem, widgetItem}, feeds,
			[]bool{true, false}, []FeedStatus{nvd, osv}, false},
		{"a feed missing from the map is incomplete", []RawItem{widgetItem}, map[string]FeedStatus{},
			[]bool{false}, []FeedStatus{{Name: "nvd"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			items := parseItems(tt.raws...)
			got := runWith(t, newWorkMeter(context.Background()), items, rowsFor(t, items), tt.feeds, nil, DefaultLimits)
			var items_ []bool
			for _, r := range got.Results {
				items_ = append(items_, r.DataComplete)
			}
			if !reflect.DeepEqual(items_, tt.wantItems) {
				t.Errorf("item data_complete = %v, want %v", items_, tt.wantItems)
			}
			if !reflect.DeepEqual(got.Feeds, tt.wantFeeds) {
				t.Errorf("feeds = %+v, want %+v", got.Feeds, tt.wantFeeds)
			}
			if got.DataComplete != tt.wantAll {
				t.Errorf("data_complete = %v, want %v", got.DataComplete, tt.wantAll)
			}
		})
	}
}

// TestEvaluateIdenticalItemsReuse checks that identical items are evaluated
// once: the meter ticks no more for two than for one, and only index and id differ.
func TestEvaluateIdenticalItemsReuse(t *testing.T) {
	t.Parallel()
	ticksFor := func(raws ...RawItem) (int, Results) {
		items := parseItems(raws...)
		r := rowsFor(t, items).packages("npm", "pkg", affectedPkg(cveA), clearPkg(cveB), cannotPkg(cveC))
		m := newWorkMeter(context.Background())
		ticks := 0
		m.onTick = func() { ticks++ }
		return ticks, runWith(t, m, items, r, feedsWith(true), nil, DefaultLimits)
	}
	one, _ := ticksFor(npmItem)
	if one == 0 {
		t.Fatal("one item ticked 0 times; the test needs comparisons")
	}
	first, second := npmItem, npmItem
	first.ID, second.ID = "first", "second"
	two, res := ticksFor(first, second)
	if two != one {
		t.Errorf("two identical items ticked %d times, one item %d", two, one)
	}
	a, b := res.Results[0], res.Results[1]
	if a.Index != 0 || b.Index != 1 || deref(a.ID) != "first" || deref(b.ID) != "second" {
		t.Errorf("index and id = (%d, %v), (%d, %v); want (0, first), (1, second)", a.Index, deref(a.ID), b.Index, deref(b.ID))
	}
	b.Index, b.ID = a.Index, a.ID
	if !reflect.DeepEqual(a, b) {
		t.Errorf("identical items answered differently:\n%s\n%s", jsonOf(t, a), jsonOf(t, b))
	}

	other := npmItem
	other.Version = "1.6.0"
	if differ, _ := ticksFor(npmItem, other); differ <= one {
		t.Errorf("two items with different versions ticked %d times, one item %d; each needs its own evaluation", differ, one)
	}
}

// TestEvaluateCancelledPartway checks that a context cancelled during an item
// with thousands of rows ends the evaluation with context.Canceled and no results.
func TestEvaluateCancelledPartway(t *testing.T) {
	t.Parallel()
	items := parseItems(npmItem, npmItem)
	var rows []PackageRow
	for i := range 3000 {
		rows = append(rows, affectedPkg(fmt.Sprintf("CVE-2026-%05d", i)))
	}
	r := rowsFor(t, items).packages("npm", "pkg", rows...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := newWorkMeter(ctx)
	ticks := 0
	m.onTick = func() {
		ticks++
		if ticks == 10 {
			cancel()
		}
	}
	got, err := evaluateItems(m, items, r.data, feedsWith(true), nil, DefaultLimits)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(got, Results{}) {
		t.Errorf("results = %+v, want none", got)
	}
	if ticks >= 1000 {
		t.Errorf("ticks = %d; evaluation went on after the context ended", ticks)
	}
}

// TestEvaluateCancelledBeforeOneRow checks that a request whose context has
// ended is refused even when its work is far below 1,000 ticks.
func TestEvaluateCancelledBeforeOneRow(t *testing.T) {
	t.Parallel()
	items := parseItems(npmItem)
	r := rowsFor(t, items).packages("npm", "pkg", affectedPkg(cveA))
	got, err := Evaluate(cancelledContext(), items, r.data, feedsWith(true), nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if !reflect.DeepEqual(got, Results{}) {
		t.Errorf("results = %+v, want none", got)
	}
}

// TestEvaluateItemWithNoForm checks that an Item with no package, product or
// error, which ParseItem never returns, is answered as invalid_form rather
// than evaluated.
func TestEvaluateItemWithNoForm(t *testing.T) {
	t.Parallel()
	items := []Item{{Index: 0, ID: "empty", Version: "1.0"}}
	got, err := Evaluate(context.Background(), items, Candidates{}, feedsWith(true), nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	r := got.Results[0]
	want := &ItemError{Code: "invalid_form", Message: itemErrorMessages["invalid_form"]}
	if r.Status != StatusInvalid || !reflect.DeepEqual(r.Error, want) || r.Component != nil || deref(r.ID) != "empty" {
		t.Errorf("result = %s, want status invalid with error invalid_form and no component", jsonOf(t, r))
	}
	if len(got.Feeds) != 0 || !got.DataComplete {
		t.Errorf("feeds = %+v, data_complete %v; want none and true, as for any invalid item", got.Feeds, got.DataComplete)
	}
}

func TestEvaluateRejectsCandidatesThatDoNotMatchKeys(t *testing.T) {
	t.Parallel()
	items := parseItems(npmItem)
	_, err := Evaluate(context.Background(), items, Candidates{}, feedsWith(true), nil)
	if err == nil {
		t.Error("Evaluate accepted candidates with no rows for the request's keys")
	}
}

// TestEvaluateResultsInRequestOrder checks index, id and component per item, in
// request order, with an invalid item among valid ones.
func TestEvaluateResultsInRequestOrder(t *testing.T) {
	t.Parallel()
	pkg, bad, cpe := npmItem, RawItem{ID: "bad", Ecosystem: "npm"}, widgetItem
	pkg.ID = "pkg"
	items := parseItems(pkg, bad, cpe)
	got := run(t, items, rowsFor(t, items)).Results
	want := []struct {
		index     int
		id        any
		component *Component
		errorCode string
	}{
		{0, "pkg", &Component{Kind: "package", Ecosystem: "npm", Name: "pkg", Version: "1.5.0"}, ""},
		{1, "bad", nil, "invalid_form"},
		{2, nil, &Component{Kind: "product", Part: "a", Vendor: "acme", Product: "widget", Version: "1.5.0"}, ""},
	}
	for i, w := range want {
		r := got[i]
		code := ""
		if r.Error != nil {
			code = r.Error.Code
		}
		if r.Index != w.index || deref(r.ID) != w.id || !reflect.DeepEqual(r.Component, w.component) || code != w.errorCode {
			t.Errorf("result %d = index %d, id %v, component %+v, error %q; want %d, %v, %+v, %q",
				i, r.Index, deref(r.ID), r.Component, code, w.index, w.id, w.component, w.errorCode)
		}
	}
}

// TestEvaluateJSON checks the response's JSON field names against design
// section 11's example, and the shapes of a package and an invalid item.
func TestEvaluateJSON(t *testing.T) {
	t.Parallel()
	lastSuccess := time.Date(2026, 11, 8, 10, 15, 0, 0, time.UTC)
	feeds := map[string]FeedStatus{"nvd": {Name: "nvd", Complete: true, LastSuccessAt: &lastSuccess}}

	t.Run("design example", func(t *testing.T) {
		t.Parallel()
		items := parseItems(RawItem{ID: "runner-node", CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", Version: "24.22.0"})
		r := rowsFor(t, items).cpes("nodejs", "node.js", cpeAt("CVE-2026-111497", nodeCPE, "23.0.0", "24.22.1"))
		enrichment := map[string]CVEEnrichment{
			"CVE-2026-111497": {Severity: ptr("HIGH"), CVSSv3Score: ptr(7.5), EPSSScore: ptr(0.01)},
		}
		got := runWith(t, newWorkMeter(context.Background()), items, r, feeds, enrichment, DefaultLimits)
		want := `{"data_complete":true,"feeds":[{"name":"nvd","complete":true,"last_success_at":"2026-11-08T10:15:00Z"}],` +
			`"results":[{"index":0,"id":"runner-node","status":"affected","reason":null,` +
			`"component":{"kind":"product","part":"a","vendor":"nodejs","product":"node.js","version":"24.22.0"},` +
			`"data_complete":true,"counts":{"affected":1,"cannot_evaluate":0,"not_affected":0,"retracted":0},` +
			`"advisories":[{"advisory_id":"CVE-2026-111497","cve_ids":["CVE-2026-111497"],"verdict":"affected","reason":null,` +
			`"fixed_version":"24.22.1","fix_major":"same",` +
			`"matched_ranges":[{"evidence":"nvd_cpe","cpe":"cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*","introduced":"23.0.0","fixed":"24.22.1"}],` +
			`"matched_ranges_total":1,"severity":"HIGH","cvss_v3_score":7.5,"epss_score":0.01,"in_cisa_kev":false}],` +
			`"advisories_truncated":false,"warnings":[],"error":null}]}`
		if s := jsonOf(t, got); s != want {
			t.Errorf("JSON =\n%s\nwant\n%s", s, want)
		}
	})

	t.Run("package and invalid items", func(t *testing.T) {
		t.Parallel()
		items := parseItems(RawItem{Ecosystem: "Ubuntu:26.04:LTS", Name: "php8.5", Version: "8.5.4-0ubuntu1.4"}, RawItem{Ecosystem: "npm"})
		got := runWith(t, newWorkMeter(context.Background()), items, rowsFor(t, items), feeds, nil, DefaultLimits)
		want := `[{"index":0,"id":null,"status":"cannot_evaluate","reason":"distro_package_not_found",` +
			`"component":{"kind":"package","ecosystem":"Ubuntu:26.04:LTS","name":"php8.5","version":"8.5.4-0ubuntu1.4"},` +
			`"data_complete":false,"counts":{"affected":0,"cannot_evaluate":0,"not_affected":0,"retracted":0},` +
			`"advisories":[],"advisories_truncated":false,"warnings":[],"error":null},` +
			`{"index":1,"id":null,"status":"invalid","reason":null,"component":null,"data_complete":false,` +
			`"counts":{"affected":0,"cannot_evaluate":0,"not_affected":0,"retracted":0},"advisories":[],` +
			`"advisories_truncated":false,"warnings":[],` +
			`"error":{"code":"invalid_form","message":"` + itemErrorMessages["invalid_form"] + `"}}]`
		if s := jsonOf(t, got.Results); s != want {
			t.Errorf("JSON =\n%s\nwant\n%s", s, want)
		}
	})
}

// TestEvaluateItemOverLimitGroupsNoRows checks that an item over its row limit,
// by its keys' total or by a key's overflow flag, is answered
// too_many_candidates before any row is grouped by advisory. A request of many
// such items (300 kernel versions over the per-key limit) otherwise allocated
// gigabytes for rows that are never evaluated. It does not run in parallel,
// because testing.AllocsPerRun counts every allocation in the process.
func TestEvaluateItemOverLimitGroupsNoRows(t *testing.T) { //nolint:paralleltest // AllocsPerRun counts the whole process
	items := parseItems(widgetItem)
	rows := make([]CPERow, 20000)
	for i := range rows {
		rows[i] = cpeAt(fmt.Sprintf("CVE-2026-%06d", i), widgetCPE, "2.0", "3.0")
	}
	_, uses := keysWithUses(items)
	feeds := feedsWith(true)

	overTotal := rowsFor(t, items).cpes("acme", "widget", rows...)
	overflowed := rowsFor(t, items).cpes("acme", "widget", rows[:50]...)
	overflowed.data.CPEs[overflowed.cpeKeys("acme", "widget")[0]].Overflow = true

	for name, c := range map[string]struct {
		data   Candidates
		limits Limits
	}{
		"rows over the item limit": {overTotal.data, Limits{ItemRows: 100, AdvisoryRanges: 1000}},
		"a key over its limit":     {overflowed.data, Limits{ItemRows: 1 << 30, AdvisoryRanges: 1000}},
	} {
		m := newWorkMeter(context.Background())
		res := evaluateItem(m, items[0], uses[0], c.data, feeds, nil, c.limits)
		if res.Reason == nil || *res.Reason != ReasonTooManyCandidates {
			t.Fatalf("%s: status %s, reason %v; want too_many_candidates", name, res.Status, res.Reason)
		}
		allocs := testing.AllocsPerRun(5, func() {
			evaluateItem(m, items[0], uses[0], c.data, feeds, nil, c.limits)
		})
		if allocs > 50 {
			t.Errorf("%s: %.0f allocations per answer, want a few, however many rows its keys hold", name, allocs)
		}
	}
}
