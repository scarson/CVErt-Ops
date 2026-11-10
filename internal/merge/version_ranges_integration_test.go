// ABOUTME: Integration tests for storing NVD CPE match ranges and CNA affected entries through the merge pipeline.
// ABOUTME: Covers real golden records, re-merge stability, material_hash stability, and the late-binding CVE ID move.
package merge_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const nodeJSCriteria = "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*"

func countRows(t *testing.T, s *testutil.TestDB, table, cveID string) int {
	t.Helper()
	var n int
	// Table names are constants in this file.
	if err := s.DB().QueryRowContext(context.Background(),
		"SELECT count(*) FROM "+table+" WHERE cve_id = $1", cveID).Scan(&n); err != nil { //nolint:gosec // G202: constant table names
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestIngest_StoresEveryBranchRangeForOneCriteria(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	patch := testutil.GoldenPatch(t, "nvd", "CVE-2026-56847")

	if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	matches, err := generated.New(s.DB()).GetCVEVulnerableCPEMatches(ctx, patch.CVEID)
	if err != nil {
		t.Fatalf("GetCVEVulnerableCPEMatches: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("got %d matches, want 3 (one per branch): %+v", len(matches), matches)
	}
	wantEnds := []string{"22.23.1", "24.18.0", "26.5.0"}
	for i, m := range matches {
		if m.CpeNormalized != nodeJSCriteria {
			t.Errorf("match %d cpe = %q", i, m.CpeNormalized)
		}
		if m.VersionEndIncluding.String != wantEnds[i] {
			t.Errorf("match %d end = %q, want %q", i, m.VersionEndIncluding.String, wantEnds[i])
		}
	}
	if got := countRows(t, s, "cve_affected_cpes", patch.CVEID); got != 1 {
		t.Errorf("cve_affected_cpes has %d rows, want 1", got)
	}
}

// Skipping a vulnerable: false CPE applies to the "what is affected" read, not to storage.
func TestIngest_VulnerableReadSkipsRunningOnPlatform(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	patch := testutil.GoldenPatch(t, "nvd", "CVE-2017-12542")

	if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if got := countRows(t, s, "cve_cpe_matches", patch.CVEID); got != 2 {
		t.Errorf("cve_cpe_matches has %d rows, want 2 (firmware and hardware)", got)
	}
	matches, err := generated.New(s.DB()).GetCVEVulnerableCPEMatches(ctx, patch.CVEID)
	if err != nil {
		t.Fatalf("GetCVEVulnerableCPEMatches: %v", err)
	}
	if len(matches) != 1 || matches[0].CpeNormalized != "cpe:2.3:o:hp:integrated_lights-out_4_firmware:*:*:*:*:*:*:*:*" {
		t.Fatalf("vulnerable matches = %+v, want the firmware only", matches)
	}
	if matches[0].VersionEndExcluding.String != "2.53" {
		t.Errorf("version_end_excluding = %q, want 2.53", matches[0].VersionEndExcluding.String)
	}
}

func TestIngest_RemovesRepeatedEntriesAndStaysStableOnRemerge(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	entry := feed.CNAAffected{
		Vendor:   "Acme",
		Product:  "Widget",
		Versions: []feed.CNAVersion{{Version: "1.0", LessThan: "1.5", Status: "affected", VersionType: "semver"}},
	}
	match := feed.CPEMatch{CPE: "cpe:2.3:a:acme:widget:*", CPENormalized: "cpe:2.3:a:acme:widget:*", VersionEndExcluding: "1.5", Vulnerable: true}
	patch := feed.CanonicalPatch{
		CVEID:       "CVE-2024-99950",
		Status:      "published",
		CPEMatches:  []feed.CPEMatch{match, match},
		CNAAffected: []feed.CNAAffected{entry, entry},
	}

	for range 2 {
		if err := merge.Ingest(ctx, s.Store, patch, "mitre"); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}

	if got := countRows(t, s, "cve_cpe_matches", patch.CVEID); got != 1 {
		t.Errorf("cve_cpe_matches has %d rows, want 1", got)
	}
	if got := countRows(t, s, "cve_cna_affected", patch.CVEID); got != 1 {
		t.Errorf("cve_cna_affected has %d rows, want 1", got)
	}
}

// A later merge that no longer carries an entry must remove it: child tables are
// recomputed from cve_sources on every merge.
func TestIngest_RecomputesRangesFromSources(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	patch := feed.CanonicalPatch{
		CVEID:  "CVE-2024-99951",
		Status: "published",
		CPEMatches: []feed.CPEMatch{
			{CPE: "cpe:2.3:a:acme:widget:*", CPENormalized: "cpe:2.3:a:acme:widget:*", VersionEndExcluding: "1.5", Vulnerable: true},
			{CPE: "cpe:2.3:a:acme:widget:*", CPENormalized: "cpe:2.3:a:acme:widget:*", VersionStartIncluding: "2.0", VersionEndExcluding: "2.5", Vulnerable: true},
		},
	}
	if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	patch.CPEMatches = patch.CPEMatches[:1]
	if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
		t.Fatalf("Ingest (narrowed): %v", err)
	}

	if got := countRows(t, s, "cve_cpe_matches", patch.CVEID); got != 1 {
		t.Errorf("cve_cpe_matches has %d rows, want 1 after the source dropped a range", got)
	}
}

// The CVE is unanalysed by NVD. Its CNA data arrives from either feed alone, and
// both together store one row, not one per feed.
func TestIngest_StoresCNAAffectedForCVEWithoutNVDAnalysis(t *testing.T) {
	const cveID = "CVE-2026-107832"

	for _, tc := range []struct {
		name    string
		sources []string
	}{
		{"NVD relay alone", []string{"nvd"}},
		{"MITRE alone", []string{"mitre"}},
		{"both", []string{"nvd", "mitre"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testutil.NewTestDB(t)
			ctx := context.Background()
			for _, source := range tc.sources {
				if err := merge.Ingest(ctx, s.Store, testutil.GoldenPatch(t, source, cveID), source); err != nil {
					t.Fatalf("Ingest %s: %v", source, err)
				}
			}

			if got := countRows(t, s, "cve_cpe_matches", cveID); got != 0 {
				t.Errorf("cve_cpe_matches has %d rows, want 0", got)
			}
			rows, err := generated.New(s.DB()).GetCVECNAAffected(ctx, cveID)
			if err != nil {
				t.Fatalf("GetCVECNAAffected: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
			}
			row := rows[0]
			if row.Vendor.String != "fastify" || row.Product.String != "fastify" || row.DefaultStatus.String != "unaffected" {
				t.Errorf("row = %s/%s default %s", row.Vendor.String, row.Product.String, row.DefaultStatus.String)
			}
			var versions []feed.CNAVersion
			if err := json.Unmarshal(row.Versions, &versions); err != nil {
				t.Fatalf("versions JSON: %v", err)
			}
			if len(versions) != 2 || versions[0].LessThan != "5.12.6" || versions[1].Status != "unaffected" {
				t.Errorf("versions = %+v", versions)
			}
		})
	}
}

// The golden NVD record relays the CNA's packageURL pkg:npm/fastify, and no other
// golden feed names that package. Merge stores its package key, which is not a
// material_hash input, so adding it does not move the hash or the modified date.
func TestIngest_StoresCNAPackageKey(t *testing.T) {
	const cveID = "CVE-2026-107832"
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	patch := testutil.GoldenPatch(t, "nvd", cveID)
	if len(patch.CNAAffected) != 1 || patch.CNAAffected[0].PackageKey != "npm/fastify" {
		t.Fatalf("golden patch CNA entries = %+v, want one with package key npm/fastify", patch.CNAAffected)
	}

	without := patch
	without.CNAAffected = []feed.CNAAffected{patch.CNAAffected[0]}
	without.CNAAffected[0].PackageKey = ""
	if err := merge.Ingest(ctx, s.Store, without, "nvd"); err != nil {
		t.Fatalf("Ingest without package key: %v", err)
	}
	cveBefore := s.MustGetCVE(t, ctx, cveID)
	if keys := cnaPackageKeys(t, s, cveID); len(keys) != 1 || keys[0].Valid {
		t.Errorf("package keys = %+v for an entry without one, want one NULL", keys)
	}

	if err := merge.Ingest(ctx, s.Store, patch, "nvd"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	cveAfter := s.MustGetCVE(t, ctx, cveID)
	if keys := cnaPackageKeys(t, s, cveID); len(keys) != 1 || keys[0].String != "npm/fastify" {
		t.Errorf("package keys = %+v, want one: npm/fastify", keys)
	}
	if cveAfter.MaterialHash != cveBefore.MaterialHash {
		t.Errorf("material_hash moved: %s -> %s", cveBefore.MaterialHash.String, cveAfter.MaterialHash.String)
	}
	if !cveAfter.DateModifiedCanonical.Equal(cveBefore.DateModifiedCanonical) {
		t.Errorf("date_modified_canonical moved: %s -> %s", cveBefore.DateModifiedCanonical, cveAfter.DateModifiedCanonical)
	}
}

// cnaPackageKeys returns the package_key of every cve_cna_affected row of a CVE.
func cnaPackageKeys(t *testing.T, s *testutil.TestDB, cveID string) []sql.NullString {
	t.Helper()
	rows, err := s.DB().QueryContext(context.Background(),
		"SELECT package_key FROM cve_cna_affected WHERE cve_id = $1 ORDER BY package_key", cveID)
	if err != nil {
		t.Fatalf("read package_key: %v", err)
	}
	defer rows.Close() //nolint:errcheck
	var keys []sql.NullString
	for rows.Next() {
		var k sql.NullString
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("scan package_key: %v", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read package_key rows: %v", err)
	}
	return keys
}

// incompressibleText returns n pseudo-random two-byte characters. PostgreSQL
// compresses long index keys, so a repeated character would fit under the btree
// row limit and prove nothing.
func incompressibleText(n int, seed uint64) string {
	r := rand.New(rand.NewPCG(seed, seed))
	var b strings.Builder
	for range n {
		b.WriteRune(rune(0x0430 + r.IntN(32))) // Cyrillic а to я: lower case, two bytes each
	}
	return b.String()
}

// CNA vendor and product can reach 2,048 characters, and a package URL has no length
// bound. The check lookup indexes must accept the longest values the merge stores,
// or a CVE with such an entry fails to merge.
func TestIngest_LongCNAValuesFitTheCheckIndexes(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// npm/ plus this name is exactly the longest key ecosystem.PackageKey keeps.
	var name strings.Builder
	r := rand.New(rand.NewPCG(3, 3))
	for range 2600 - len("npm/") {
		name.WriteByte(byte('a' + r.IntN(26)))
	}
	raw, err := json.Marshal([]map[string]string{{
		"vendor":     incompressibleText(2048, 1),
		"product":    incompressibleText(2048, 2),
		"packageURL": "pkg:npm/" + name.String(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries := feed.ParseCNAAffected(raw, "CVE-2024-99953")
	if len(entries) != 1 {
		t.Fatalf("parsed %d entries, want 1", len(entries))
	}
	if len(entries[0].PackageKey) != 2600 {
		t.Fatalf("key length = %d, want 2600", len(entries[0].PackageKey))
	}

	patch := feed.CanonicalPatch{CVEID: "CVE-2024-99953", Status: "published", CNAAffected: entries}
	if err := merge.Ingest(ctx, s.Store, patch, "mitre"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if keys := cnaPackageKeys(t, s, patch.CVEID); len(keys) != 1 || keys[0].String != "npm/"+name.String() {
		t.Errorf("stored %d keys, want the 2600-byte key", len(keys))
	}
}

// NVD's relay is treated as a copy of the MITRE record, which is only safe while
// the two agree. Real records from both feeds pin that they do.
func TestGoldenNVDRelayMatchesMITRERecord(t *testing.T) {
	for _, cveID := range []string{"CVE-2026-107832", "CVE-2026-56847", "CVE-2026-111497"} {
		nvd := testutil.GoldenPatch(t, "nvd", cveID)
		mitre := testutil.GoldenPatch(t, "mitre", cveID)
		if len(nvd.CNAAffected) == 0 {
			t.Errorf("%s: NVD relay carries no CNA data", cveID)
		}
		if !reflect.DeepEqual(nvd.CNAAffected, mitre.CNAAffected) {
			t.Errorf("%s: NVD relay %+v differs from MITRE %+v", cveID, nvd.CNAAffected, mitre.CNAAffected)
		}
	}
}

// A CNA entry with no versions must store an empty array: API clients read versions as a list.
func TestIngest_CNAAffectedWithoutVersionsStoresEmptyArray(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	patch := feed.CanonicalPatch{
		CVEID:       "CVE-2024-99952",
		Status:      "published",
		CNAAffected: []feed.CNAAffected{{Vendor: "Acme", Product: "Widget", DefaultStatus: "affected"}},
	}
	if err := merge.Ingest(ctx, s.Store, patch, "mitre"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	rows, err := generated.New(s.DB()).GetCVECNAAffected(ctx, patch.CVEID)
	if err != nil {
		t.Fatalf("GetCVECNAAffected: %v", err)
	}
	if len(rows) != 1 || string(rows[0].Versions) != "[]" {
		t.Errorf("rows = %+v, want one row with versions []", rows)
	}
}

// A CVE stored without ranges gets them on its next merge. The stored hash and
// date_modified_canonical must not move then, or every matching rule fires again.
// The golden CVEs cover vulnerable: false platform CPEs and one criteria string
// repeated across branches, which are the two inputs at risk.
func TestIngest_AddingRangesLeavesMaterialHashAndModifiedDateAlone(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	for _, tc := range []struct{ source, cveID string }{
		{"nvd", "CVE-2017-12542"},
		{"nvd", "CVE-2026-3909"},
		{"nvd", "CVE-2026-56847"},
		{"nvd", "CVE-2021-44228"},
		{"mitre", "CVE-2025-40110"},
	} {
		t.Run(tc.cveID, func(t *testing.T) {
			patch := testutil.GoldenPatch(t, tc.source, tc.cveID)
			if len(patch.CPEMatches) == 0 && len(patch.CNAAffected) == 0 {
				t.Fatalf("golden patch carries no ranges: the test would prove nothing")
			}

			before := patch
			before.CPEMatches = nil
			before.CNAAffected = nil
			if err := merge.Ingest(ctx, s.Store, before, tc.source); err != nil {
				t.Fatalf("Ingest without ranges: %v", err)
			}
			cveBefore := s.MustGetCVE(t, ctx, tc.cveID)

			if err := merge.Ingest(ctx, s.Store, patch, tc.source); err != nil {
				t.Fatalf("Ingest with ranges: %v", err)
			}
			cveAfter := s.MustGetCVE(t, ctx, tc.cveID)

			if cveAfter.MaterialHash != cveBefore.MaterialHash {
				t.Errorf("material_hash moved: %s -> %s", cveBefore.MaterialHash.String, cveAfter.MaterialHash.String)
			}
			if !cveAfter.DateModifiedCanonical.Equal(cveBefore.DateModifiedCanonical) {
				t.Errorf("date_modified_canonical moved: %s -> %s", cveBefore.DateModifiedCanonical, cveAfter.DateModifiedCanonical)
			}
			stored := countRows(t, s, "cve_cpe_matches", tc.cveID) + countRows(t, s, "cve_cna_affected", tc.cveID)
			if stored == 0 {
				t.Error("no range rows stored by the second merge")
			}
		})
	}
}

func TestIngest_MigrateCVEPK_MovesRangeRows(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	oldID, newID := "GHSA-rang-move-aaaa", "CVE-2024-99953"
	patch := feed.CanonicalPatch{
		CVEID:       oldID,
		SourceID:    oldID,
		Status:      "published",
		CPEMatches:  []feed.CPEMatch{{CPE: "cpe:2.3:a:acme:widget:*", CPENormalized: "cpe:2.3:a:acme:widget:*", VersionEndExcluding: "1.5", Vulnerable: true}},
		CNAAffected: []feed.CNAAffected{{Vendor: "Acme", Product: "Widget"}},
	}
	if err := merge.Ingest(ctx, s.Store, patch, "ghsa"); err != nil {
		t.Fatalf("Ingest (native ID): %v", err)
	}

	patch.CVEID = newID
	if err := merge.Ingest(ctx, s.Store, patch, "ghsa"); err != nil {
		t.Fatalf("Ingest (CVE ID): %v", err)
	}

	for _, table := range []string{"cve_cpe_matches", "cve_cna_affected"} {
		if got := countRows(t, s, table, oldID); got != 0 {
			t.Errorf("%s has %d rows orphaned under %s", table, got, oldID)
		}
		if got := countRows(t, s, table, newID); got != 1 {
			t.Errorf("%s has %d rows under %s, want 1", table, got, newID)
		}
	}
}

func TestIngest_MigrateCVEPK_TargetExists_RemovesOldRangeRows(t *testing.T) {
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	oldID, newID := "GHSA-rang-coll-aaaa", "CVE-2024-99954"
	match := feed.CPEMatch{CPE: "cpe:2.3:a:acme:widget:*", CPENormalized: "cpe:2.3:a:acme:widget:*", VersionEndExcluding: "1.5", Vulnerable: true}
	ghsa := feed.CanonicalPatch{
		CVEID:       oldID,
		SourceID:    oldID,
		Status:      "published",
		CPEMatches:  []feed.CPEMatch{match},
		CNAAffected: []feed.CNAAffected{{Vendor: "Acme", Product: "Widget"}},
	}
	if err := merge.Ingest(ctx, s.Store, ghsa, "ghsa"); err != nil {
		t.Fatalf("Ingest (native ID): %v", err)
	}
	nvdPatch := feed.CanonicalPatch{CVEID: newID, Status: "published", CPEMatches: []feed.CPEMatch{match}}
	if err := merge.Ingest(ctx, s.Store, nvdPatch, "nvd"); err != nil {
		t.Fatalf("Ingest (NVD): %v", err)
	}

	ghsa.CVEID = newID
	if err := merge.Ingest(ctx, s.Store, ghsa, "ghsa"); err != nil {
		t.Fatalf("Ingest (alias, target exists): %v", err)
	}

	for _, table := range []string{"cve_cpe_matches", "cve_cna_affected"} {
		if got := countRows(t, s, table, oldID); got != 0 {
			t.Errorf("%s has %d rows orphaned under %s", table, got, oldID)
		}
		if got := countRows(t, s, table, newID); got != 1 {
			t.Errorf("%s has %d rows under %s, want 1", table, got, newID)
		}
	}
}
