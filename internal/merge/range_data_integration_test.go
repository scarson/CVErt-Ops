// ABOUTME: Integration tests for per-branch ranges, one row per advisory, and withdrawal.
// ABOUTME: These are the acceptance tests for requirements DATA-1, DATA-4 and DATA-5.
package merge_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func mustIngest(t *testing.T, s *testutil.TestDB, patch feed.CanonicalPatch, source string) {
	t.Helper()
	if err := merge.Ingest(context.Background(), s.Store, patch, source); err != nil {
		t.Fatalf("Ingest(%s, %s): %v", patch.CVEID, source, err)
	}
}

func TestIngest_KeepsOneRangePerBranch(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	mustIngest(t, s, feed.CanonicalPatch{
		CVEID: "CVE-2026-20001", SourceID: "GHSA-branch",
		AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "node", Introduced: "22.0.0", Fixed: "22.23.4"},
			{Ecosystem: "npm", PackageName: "node", Introduced: "24.0.0", Fixed: "24.22.1"},
			{Ecosystem: "npm", PackageName: "node", Introduced: "26.0.0", Fixed: "26.12.1"},
		},
	}, "ghsa")

	rows, err := s.DB().QueryContext(context.Background(),
		"SELECT introduced, fixed FROM cve_affected_packages WHERE cve_id = $1 ORDER BY fixed", "CVE-2026-20001")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close() //nolint:errcheck // read-only query in a test
	var got [][2]string
	for rows.Next() {
		var pair [2]string
		if err := rows.Scan(&pair[0], &pair[1]); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, pair)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	want := [][2]string{{"22.0.0", "22.23.4"}, {"24.0.0", "24.22.1"}, {"26.0.0", "26.12.1"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ranges = %v, want %v", got, want)
	}
}

func TestIngest_OSVAdvisoriesAllSurviveInAnyOrder(t *testing.T) {
	t.Parallel()
	const cveID = "CVE-2026-20002"
	ghsa := feed.CanonicalPatch{CVEID: cveID, SourceID: "GHSA-a", AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "PyPI", PackageName: "x", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0"},
	}}
	pysec := feed.CanonicalPatch{CVEID: cveID, SourceID: "PYSEC-b", AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "PyPI", PackageName: "x", RangeType: "ECOSYSTEM", Introduced: "2.0", Fixed: "2.5"},
	}}
	bare := feed.CanonicalPatch{CVEID: cveID, SourceID: cveID}
	permutations := [][]feed.CanonicalPatch{
		{ghsa, pysec, bare}, {ghsa, bare, pysec}, {pysec, ghsa, bare},
		{pysec, bare, ghsa}, {bare, ghsa, pysec}, {bare, pysec, ghsa},
	}

	hashes := make(map[string]bool)
	for _, order := range permutations {
		s := testutil.NewTestDB(t)
		for _, p := range order {
			mustIngest(t, s, p, "osv")
		}
		var sources, ranges int
		var hash string
		db := s.DB()
		if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM cve_sources WHERE cve_id = $1", cveID).Scan(&sources); err != nil {
			t.Fatalf("count sources: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), "SELECT count(*) FROM cve_affected_packages WHERE cve_id = $1", cveID).Scan(&ranges); err != nil {
			t.Fatalf("count ranges: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), "SELECT material_hash FROM cves WHERE cve_id = $1", cveID).Scan(&hash); err != nil {
			t.Fatalf("read hash: %v", err)
		}
		if sources != 3 || ranges != 2 {
			t.Errorf("sources = %d, ranges = %d, want 3 and 2", sources, ranges)
		}
		hashes[hash] = true
	}
	if len(hashes) != 1 {
		t.Errorf("material_hash varied with processing order: %v", hashes)
	}
}

func TestSeedCorpus_StoresOnlyCanonicalEcosystems(t *testing.T) {
	s := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, s)
	ctx := context.Background()

	var stale int
	if err := s.DB().QueryRowContext(ctx, `SELECT count(*) FROM cve_affected_packages
		WHERE ecosystem IN ('pip','composer','rust','erlang','maven','go','nuget','rubygems','pub')`).Scan(&stale); err != nil {
		t.Fatalf("count stale: %v", err)
	}
	if stale != 0 {
		t.Errorf("%d rows use a GHSA ecosystem spelling", stale)
	}
	var pypi int
	if err := s.DB().QueryRowContext(ctx,
		"SELECT count(*) FROM cve_affected_packages WHERE cve_id = 'CVE-2021-42771' AND ecosystem = 'PyPI'").Scan(&pypi); err != nil {
		t.Fatalf("count PyPI: %v", err)
	}
	if pypi == 0 {
		t.Error("CVE-2021-42771 has no PyPI row")
	}
	var others int
	if err := s.DB().QueryRowContext(ctx,
		"SELECT count(DISTINCT ecosystem) FROM cve_affected_packages WHERE cve_id = 'CVE-2021-42771'").Scan(&others); err != nil {
		t.Fatalf("count ecosystems: %v", err)
	}
	if others != 1 {
		t.Errorf("CVE-2021-42771 has %d ecosystem values, want 1", others)
	}
}

func TestIngest_WithdrawnAdvisoryLeavesCVEIntact(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveID = "CVE-2026-20003"
	score := 9.8
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "Analyzed", CVSSv3Score: &score}, "nvd")
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, SourceID: "GHSA-gone", IsWithdrawn: true, Status: "withdrawn",
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "gone", Introduced: "0", Fixed: "1.0.0"}},
	}, "osv")

	var status string
	var got *float64
	if err := s.DB().QueryRowContext(context.Background(), "SELECT status, cvss_v3_score FROM cves WHERE cve_id = $1", cveID).Scan(&status, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != "Analyzed" || got == nil || *got != score {
		t.Errorf("status = %q, score = %v, want Analyzed and %v", status, got, score)
	}
	if n := countRows(t, s, "cve_affected_packages", cveID); n != 0 {
		t.Errorf("%d package rows from a withdrawn advisory", n)
	}
}

func TestIngest_EmptySourceIDStoresCVEID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveID = "CVE-2026-20004"
	for _, status := range []string{"first", "second"} {
		mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, Status: status}, "internal-scanner")
	}
	var count int
	var sourceID string
	if err := s.DB().QueryRowContext(context.Background(),
		"SELECT count(*), min(source_id) FROM cve_sources WHERE cve_id = $1", cveID).Scan(&count, &sourceID); err != nil {
		t.Fatalf("read: %v", err)
	}
	if count != 1 || sourceID != cveID {
		t.Errorf("count = %d, source_id = %q, want 1 and %q", count, sourceID, cveID)
	}
}

func TestIngest_SoleWithdrawnAdvisoryTombstones(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveID = "CVE-2026-20005"
	score := 7.5
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, SourceID: "GHSA-sole", IsWithdrawn: true, Status: "withdrawn", CVSSv3Score: &score,
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "x", Introduced: "0", Fixed: "1.0.0"}},
	}, "ghsa")

	var status string
	var got *float64
	if err := s.DB().QueryRowContext(context.Background(), "SELECT status, cvss_v3_score FROM cves WHERE cve_id = $1", cveID).Scan(&status, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != "withdrawn" || got != nil {
		t.Errorf("status = %q, score = %v, want withdrawn and no score", status, got)
	}
	if n := countRows(t, s, "cve_affected_packages", cveID); n != 0 {
		t.Errorf("%d package rows on a tombstoned CVE", n)
	}
}

func TestIngest_RejectedByMITREWithLiveNVD(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	const cveID = "CVE-2026-20006"
	score := 5.0
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "Analyzed", CVSSv3Score: &score}, "nvd")
	mustIngest(t, s, feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "REJECTED", IsWithdrawn: true}, "mitre")

	var status string
	var got *float64
	if err := s.DB().QueryRowContext(context.Background(), "SELECT status, cvss_v3_score FROM cves WHERE cve_id = $1", cveID).Scan(&status, &got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if status != "REJECTED" || got != nil {
		t.Errorf("status = %q, score = %v, want REJECTED and no score", status, got)
	}
}

func TestIngest_StoredRowsDoNotDependOnSourceOrder(t *testing.T) {
	t.Parallel()
	const cveID = "CVE-2026-20007"
	const cpe = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
	first := feed.CanonicalPatch{CVEID: cveID, SourceID: cveID,
		References:   []feed.ReferenceEntry{{URL: "https://example.com/a", Tags: []string{"from-nvd"}}},
		AffectedCPEs: []feed.AffectedCPE{{CPE: "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*", CPENormalized: cpe}},
	}
	second := feed.CanonicalPatch{CVEID: cveID, SourceID: "GHSA-order",
		References:   []feed.ReferenceEntry{{URL: "https://example.com/a", Tags: []string{"from-ghsa"}}},
		AffectedCPEs: []feed.AffectedCPE{{CPE: "cpe:2.3:a:VENDOR:PRODUCT:1.0:*:*:*:*:*:*:*", CPENormalized: cpe}},
	}

	read := func(s *testutil.TestDB) [2]string {
		t.Helper()
		var tags, spelling string
		db := s.DB()
		if err := db.QueryRowContext(context.Background(), "SELECT array_to_string(tags, ',') FROM cve_references WHERE cve_id = $1", cveID).Scan(&tags); err != nil {
			t.Fatalf("read references: %v", err)
		}
		if err := db.QueryRowContext(context.Background(), "SELECT cpe FROM cve_affected_cpes WHERE cve_id = $1", cveID).Scan(&spelling); err != nil {
			t.Fatalf("read CPEs: %v", err)
		}
		return [2]string{tags, spelling}
	}

	a := testutil.NewTestDB(t)
	mustIngest(t, a, first, "nvd")
	mustIngest(t, a, second, "ghsa")
	b := testutil.NewTestDB(t)
	mustIngest(t, b, second, "ghsa")
	mustIngest(t, b, first, "nvd")

	if gotA, gotB := read(a), read(b); gotA != gotB {
		t.Errorf("stored rows differ by order: %v vs %v", gotA, gotB)
	}
}
