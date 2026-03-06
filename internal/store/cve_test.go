// ABOUTME: Integration tests for CVE search, read, and detail queries against real Postgres.
// ABOUTME: Validates FTS, all SearchCVEs filter branches, GetCVE, GetCVEDetail, GetCVESources, GetCVESnapshot.
package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSearchCVEs_FTSBasic(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed two CVEs with distinct descriptions.
	db.SeedTestCVE(t, "CVE-2024-1111", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Buffer overflow in libfoo allows remote code execution",
	})
	db.SeedTestCVE(t, "CVE-2024-2222", "medium", &testutil.SeedCVEOpts{
		DescriptionPrimary: "SQL injection in web admin panel",
	})

	// Search for "buffer overflow" — should match only CVE-2024-1111.
	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "buffer overflow", Limit: 10}) //nolint:exhaustruct // test: only FTS field
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-1111" {
		t.Errorf("expected CVE-2024-1111, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_FTSByCVEID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-3333", "critical", nil)
	db.SeedTestCVE(t, "CVE-2024-4444", "low", nil)

	// Search by CVE ID text — the CVE ID is indexed with weight D.
	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "CVE-2024-3333", Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-3333" {
		t.Errorf("expected CVE-2024-3333, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_FTSNoMatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-5555", "high", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Memory corruption in kernel module",
	})

	results, err := db.SearchCVEs(ctx, store.SearchParams{Q: "javascript prototype pollution", Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestSearchCVEs_FTSWithSeverityFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-6666", "critical", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Remote code execution via deserialization",
	})
	db.SeedTestCVE(t, "CVE-2024-7777", "low", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Remote code execution via path traversal",
	})

	// Both match "remote code execution" but only one is critical.
	results, err := db.SearchCVEs(ctx, store.SearchParams{ //nolint:exhaustruct // test
		Q:        "remote code execution",
		Severity: []string{"critical"},
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-6666" {
		t.Errorf("expected CVE-2024-6666, got %s", results[0].CveID)
	}
}

// ── SearchCVEs filter tests ───────────────────────────────────────────────────

// ptrFloat64 returns a pointer to the given float64.
func ptrFloat64(v float64) *float64 { return &v }

// ptrTime returns a pointer to the given time.Time.
func ptrTime(v time.Time) *time.Time { return &v }

// ptrString returns a pointer to the given string.
func ptrString(v string) *string { return &v }

// ptrBool returns a pointer to the given bool.
func ptrBool(v bool) *bool { return &v }

func TestSearchCVEs_CVSSMinFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8001", "high", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(9.8)})
	db.SeedTestCVE(t, "CVE-2024-8002", "medium", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(5.0)})
	db.SeedTestCVE(t, "CVE-2024-8003", "low", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(2.0)})

	results, err := db.SearchCVEs(ctx, store.SearchParams{CVSSMin: ptrFloat64(5.0), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs CVSSMin: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (scores >= 5.0), got %d", len(results))
	}
	for _, r := range results {
		if !r.CvssV3Score.Valid || r.CvssV3Score.Float64 < 5.0 {
			t.Errorf("CVE %s has cvss_v3_score %v, expected >= 5.0", r.CveID, r.CvssV3Score)
		}
	}
}

func TestSearchCVEs_CVSSMaxFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8011", "high", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(9.8)})
	db.SeedTestCVE(t, "CVE-2024-8012", "medium", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(5.0)})
	db.SeedTestCVE(t, "CVE-2024-8013", "low", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(2.0)})

	results, err := db.SearchCVEs(ctx, store.SearchParams{CVSSMax: ptrFloat64(5.0), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs CVSSMax: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results (scores <= 5.0), got %d", len(results))
	}
	for _, r := range results {
		if !r.CvssV3Score.Valid || r.CvssV3Score.Float64 > 5.0 {
			t.Errorf("CVE %s has cvss_v3_score %v, expected <= 5.0", r.CveID, r.CvssV3Score)
		}
	}
}

func TestSearchCVEs_DateFromFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	old := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	db.SeedTestCVE(t, "CVE-2024-8021", "high", &testutil.SeedCVEOpts{DateModifiedCanonical: &old})
	db.SeedTestCVE(t, "CVE-2024-8022", "medium", &testutil.SeedCVEOpts{DateModifiedCanonical: &recent})

	cutoff := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	results, err := db.SearchCVEs(ctx, store.SearchParams{DateFrom: ptrTime(cutoff), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs DateFrom: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (after 2024-01-01), got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8022" {
		t.Errorf("expected CVE-2024-8022, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_DateToFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	old := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	db.SeedTestCVE(t, "CVE-2024-8031", "high", &testutil.SeedCVEOpts{DateModifiedCanonical: &old})
	db.SeedTestCVE(t, "CVE-2024-8032", "medium", &testutil.SeedCVEOpts{DateModifiedCanonical: &recent})

	cutoff := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	results, err := db.SearchCVEs(ctx, store.SearchParams{DateTo: ptrTime(cutoff), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs DateTo: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (before 2024-01-01), got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8031" {
		t.Errorf("expected CVE-2024-8031, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_CWEIDFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8041", "high", nil)
	db.SeedTestCVE(t, "CVE-2024-8042", "medium", nil)

	// Manually set cwe_ids arrays.
	_, err := db.DB().ExecContext(ctx, "UPDATE cves SET cwe_ids = $1 WHERE cve_id = $2", pq.Array([]string{"CWE-79", "CWE-89"}), "CVE-2024-8041")
	if err != nil {
		t.Fatalf("set cwe_ids for 8041: %v", err)
	}
	_, err = db.DB().ExecContext(ctx, "UPDATE cves SET cwe_ids = $1 WHERE cve_id = $2", pq.Array([]string{"CWE-200"}), "CVE-2024-8042")
	if err != nil {
		t.Fatalf("set cwe_ids for 8042: %v", err)
	}

	results, err := db.SearchCVEs(ctx, store.SearchParams{CWEID: ptrString("CWE-79"), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs CWEID: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for CWE-79, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8041" {
		t.Errorf("expected CVE-2024-8041, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_EcosystemFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8051", "high", nil)
	db.SeedTestCVE(t, "CVE-2024-8052", "medium", nil)

	// Insert affected packages.
	_, err := db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name) VALUES ($1, $2, $3)",
		"CVE-2024-8051", "npm", "lodash",
	)
	if err != nil {
		t.Fatalf("insert package 8051: %v", err)
	}
	_, err = db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name) VALUES ($1, $2, $3)",
		"CVE-2024-8052", "PyPI", "requests",
	)
	if err != nil {
		t.Fatalf("insert package 8052: %v", err)
	}

	results, err := db.SearchCVEs(ctx, store.SearchParams{Ecosystem: ptrString("npm"), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs Ecosystem: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for npm, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8051" {
		t.Errorf("expected CVE-2024-8051, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_EcosystemAndPackageNameFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8061", "high", nil)
	db.SeedTestCVE(t, "CVE-2024-8062", "medium", nil)

	// Both are npm but different packages.
	_, err := db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name) VALUES ($1, $2, $3)",
		"CVE-2024-8061", "npm", "express",
	)
	if err != nil {
		t.Fatalf("insert package 8061: %v", err)
	}
	_, err = db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name) VALUES ($1, $2, $3)",
		"CVE-2024-8062", "npm", "axios",
	)
	if err != nil {
		t.Fatalf("insert package 8062: %v", err)
	}

	results, err := db.SearchCVEs(ctx, store.SearchParams{ //nolint:exhaustruct // test
		Ecosystem:   ptrString("npm"),
		PackageName: ptrString("express"),
		Limit:       10,
	})
	if err != nil {
		t.Fatalf("SearchCVEs Ecosystem+PackageName: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result for npm/express, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8061" {
		t.Errorf("expected CVE-2024-8061, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_InCISAKEVFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8071", "high", &testutil.SeedCVEOpts{InCisaKev: true})
	db.SeedTestCVE(t, "CVE-2024-8072", "medium", nil) // InCisaKev defaults to false

	results, err := db.SearchCVEs(ctx, store.SearchParams{InCISAKEV: ptrBool(true), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs InCISAKEV: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 KEV result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8071" {
		t.Errorf("expected CVE-2024-8071, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_ExploitAvailableFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8081", "high", &testutil.SeedCVEOpts{ExploitAvailable: true})
	db.SeedTestCVE(t, "CVE-2024-8082", "medium", nil) // ExploitAvailable defaults to false

	results, err := db.SearchCVEs(ctx, store.SearchParams{ExploitAvail: ptrBool(true), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs ExploitAvail: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 exploit-available result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8081" {
		t.Errorf("expected CVE-2024-8081, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_EPSSMinFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8091", "high", &testutil.SeedCVEOpts{EpssScore: ptrFloat64(0.95)})
	db.SeedTestCVE(t, "CVE-2024-8092", "medium", &testutil.SeedCVEOpts{EpssScore: ptrFloat64(0.10)})
	db.SeedTestCVE(t, "CVE-2024-8093", "low", nil) // NULL epss_score

	results, err := db.SearchCVEs(ctx, store.SearchParams{EPSSMin: ptrFloat64(0.50), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs EPSSMin: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (EPSS >= 0.50), got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8091" {
		t.Errorf("expected CVE-2024-8091, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_EPSSMaxFilter(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8101", "high", &testutil.SeedCVEOpts{EpssScore: ptrFloat64(0.95)})
	db.SeedTestCVE(t, "CVE-2024-8102", "medium", &testutil.SeedCVEOpts{EpssScore: ptrFloat64(0.10)})
	db.SeedTestCVE(t, "CVE-2024-8103", "low", nil) // NULL epss_score

	// EPSSMax: COALESCE(epss_score, 2) <= 0.50 — NULL rows get sentinel 2, so they're excluded.
	results, err := db.SearchCVEs(ctx, store.SearchParams{EPSSMax: ptrFloat64(0.50), Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs EPSSMax: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result (EPSS <= 0.50), got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8102" {
		t.Errorf("expected CVE-2024-8102, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_KeysetCursorPagination(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 5 CVEs with distinct timestamps to ensure deterministic ordering.
	for i := range 5 {
		ts := time.Date(2025, 1, 1+i, 0, 0, 0, 0, time.UTC)
		id := "CVE-2024-811" + string(rune('0'+i))
		db.SeedTestCVE(t, id, "high", &testutil.SeedCVEOpts{DateModifiedCanonical: &ts})
	}

	// First page: 3 items.
	page1, err := db.SearchCVEs(ctx, store.SearchParams{Limit: 3}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs page1: %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1: expected 3, got %d", len(page1))
	}

	// Second page using the cursor from last item of page1.
	last := page1[len(page1)-1]
	page2, err := db.SearchCVEs(ctx, store.SearchParams{ //nolint:exhaustruct // test
		CursorDate:  ptrTime(last.DateModifiedCanonical),
		CursorCVEID: last.CveID,
		Limit:       3,
	})
	if err != nil {
		t.Fatalf("SearchCVEs page2: %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: expected 2, got %d", len(page2))
	}

	// Verify no overlap between pages.
	seen := map[string]bool{}
	for _, r := range page1 {
		seen[r.CveID] = true
	}
	for _, r := range page2 {
		if seen[r.CveID] {
			t.Errorf("overlap: %s appeared in both pages", r.CveID)
		}
	}
}

func TestSearchCVEs_LimitPlusOneHasMore(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed 3 CVEs.
	for i := range 3 {
		ts := time.Date(2025, 2, 1+i, 0, 0, 0, 0, time.UTC)
		id := "CVE-2024-812" + string(rune('0'+i))
		db.SeedTestCVE(t, id, "medium", &testutil.SeedCVEOpts{DateModifiedCanonical: &ts})
	}

	// Request Limit=3 (caller would typically pass pageSize+1 to detect more).
	results, err := db.SearchCVEs(ctx, store.SearchParams{Limit: 3}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs: %v", err)
	}
	// All 3 returned — this is the exact page size, so hasMore would be false.
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	// Request Limit=2 with 3 CVEs in DB — caller would see len(results)==2 < 3 available.
	// The Limit+1 pattern: caller sends limit+1 to SearchCVEs, checks len > limit.
	results2, err := db.SearchCVEs(ctx, store.SearchParams{Limit: 2}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs limit+1: %v", err)
	}
	if len(results2) != 2 {
		t.Fatalf("expected 2 results with Limit=2, got %d", len(results2))
	}
}

func TestSearchCVEs_MultipleCombinedFilters(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-8131", "critical", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(9.8)})
	db.SeedTestCVE(t, "CVE-2024-8132", "critical", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(4.0)})
	db.SeedTestCVE(t, "CVE-2024-8133", "high", &testutil.SeedCVEOpts{CvssV3Score: ptrFloat64(9.5)})

	// Severity=critical AND CVSSMin=7.0 — only CVE-2024-8131 qualifies.
	results, err := db.SearchCVEs(ctx, store.SearchParams{ //nolint:exhaustruct // test
		Severity: []string{"critical"},
		CVSSMin:  ptrFloat64(7.0),
		Limit:    10,
	})
	if err != nil {
		t.Fatalf("SearchCVEs combined: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].CveID != "CVE-2024-8131" {
		t.Errorf("expected CVE-2024-8131, got %s", results[0].CveID)
	}
}

func TestSearchCVEs_EmptyTableReturnsEmpty(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// No CVEs seeded.
	results, err := db.SearchCVEs(ctx, store.SearchParams{Limit: 10}) //nolint:exhaustruct // test
	if err != nil {
		t.Fatalf("SearchCVEs empty: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results from empty table, got %d", len(results))
	}
}

// ── GetCVE tests ──────────────────────────────────────────────────────────────

func TestGetCVE_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9001", "critical", &testutil.SeedCVEOpts{
		DescriptionPrimary: "Critical RCE in libbar",
		CvssV3Score:        ptrFloat64(9.8),
	})

	cve, err := db.GetCVE(ctx, "CVE-2024-9001")
	if err != nil {
		t.Fatalf("GetCVE: %v", err)
	}
	if cve == nil {
		t.Fatal("GetCVE returned nil for existing CVE")
	}
	if cve.CveID != "CVE-2024-9001" {
		t.Errorf("CveID = %q, want CVE-2024-9001", cve.CveID)
	}
	if cve.Severity.String != "critical" {
		t.Errorf("Severity = %q, want critical", cve.Severity.String)
	}
	if !cve.CvssV3Score.Valid || cve.CvssV3Score.Float64 != 9.8 {
		t.Errorf("CvssV3Score = %v, want 9.8", cve.CvssV3Score)
	}
}

func TestGetCVE_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	cve, err := db.GetCVE(ctx, "CVE-0000-0000")
	if err != nil {
		t.Fatalf("GetCVE(not found): %v", err)
	}
	if cve != nil {
		t.Error("GetCVE should return nil for non-existent CVE")
	}
}

// ── GetCVEDetail tests ────────────────────────────────────────────────────────

func TestGetCVEDetail_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9011", "high", nil)

	// Seed child data.
	_, err := db.DB().ExecContext(ctx,
		"INSERT INTO cve_references (cve_id, url, url_canonical, tags) VALUES ($1, $2, $3, $4)",
		"CVE-2024-9011", "https://example.com/vuln", "example.com/vuln", pq.Array([]string{"advisory"}),
	)
	if err != nil {
		t.Fatalf("insert reference: %v", err)
	}

	_, err = db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_packages (cve_id, ecosystem, package_name) VALUES ($1, $2, $3)",
		"CVE-2024-9011", "npm", "vulnerable-pkg",
	)
	if err != nil {
		t.Fatalf("insert package: %v", err)
	}

	_, err = db.DB().ExecContext(ctx,
		"INSERT INTO cve_affected_cpes (cve_id, cpe, cpe_normalized) VALUES ($1, $2, $3)",
		"CVE-2024-9011", "cpe:2.3:a:vendor:product:1.0", "cpe:2.3:a:vendor:product:1.0",
	)
	if err != nil {
		t.Fatalf("insert cpe: %v", err)
	}

	cve, refs, pkgs, cpes, err := db.GetCVEDetail(ctx, "CVE-2024-9011")
	if err != nil {
		t.Fatalf("GetCVEDetail: %v", err)
	}
	if cve == nil {
		t.Fatal("GetCVEDetail returned nil CVE")
	}
	if cve.CveID != "CVE-2024-9011" {
		t.Errorf("CveID = %q, want CVE-2024-9011", cve.CveID)
	}
	if len(refs) != 1 {
		t.Errorf("refs count = %d, want 1", len(refs))
	}
	if len(pkgs) != 1 {
		t.Errorf("packages count = %d, want 1", len(pkgs))
	}
	if len(cpes) != 1 {
		t.Errorf("CPEs count = %d, want 1", len(cpes))
	}
}

func TestGetCVEDetail_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	cve, refs, pkgs, cpes, err := db.GetCVEDetail(ctx, "CVE-0000-0001")
	if err != nil {
		t.Fatalf("GetCVEDetail(not found): %v", err)
	}
	if cve != nil || refs != nil || pkgs != nil || cpes != nil {
		t.Error("GetCVEDetail should return all nils for non-existent CVE")
	}
}

func TestGetCVEDetail_NoChildRows(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9021", "low", nil)

	cve, refs, pkgs, cpes, err := db.GetCVEDetail(ctx, "CVE-2024-9021")
	if err != nil {
		t.Fatalf("GetCVEDetail(no children): %v", err)
	}
	if cve == nil {
		t.Fatal("GetCVEDetail returned nil CVE for existing row")
	}
	// sqlc returns nil (not empty slice) when no rows match.
	if len(refs) != 0 {
		t.Errorf("refs should be nil or empty, got %d", len(refs))
	}
	if len(pkgs) != 0 {
		t.Errorf("packages should be nil or empty, got %d", len(pkgs))
	}
	if len(cpes) != 0 {
		t.Errorf("CPEs should be nil or empty, got %d", len(cpes))
	}
}

// ── GetCVESources tests ───────────────────────────────────────────────────────

func TestGetCVESources_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9031", "high", nil)

	// Insert two sources.
	_, err := db.DB().ExecContext(ctx,
		`INSERT INTO cve_sources (cve_id, source_name, normalized_json) VALUES ($1, $2, $3)`,
		"CVE-2024-9031", "nvd", `{"id":"CVE-2024-9031"}`,
	)
	if err != nil {
		t.Fatalf("insert source nvd: %v", err)
	}
	_, err = db.DB().ExecContext(ctx,
		`INSERT INTO cve_sources (cve_id, source_name, normalized_json) VALUES ($1, $2, $3)`,
		"CVE-2024-9031", "mitre", `{"id":"CVE-2024-9031"}`,
	)
	if err != nil {
		t.Fatalf("insert source mitre: %v", err)
	}

	sources, err := db.GetCVESources(ctx, "CVE-2024-9031")
	if err != nil {
		t.Fatalf("GetCVESources: %v", err)
	}
	if len(sources) != 2 {
		t.Fatalf("expected 2 sources, got %d", len(sources))
	}
	// Ordered by source_name.
	if sources[0].SourceName != "mitre" {
		t.Errorf("first source = %q, want mitre (alphabetical order)", sources[0].SourceName)
	}
	if sources[1].SourceName != "nvd" {
		t.Errorf("second source = %q, want nvd", sources[1].SourceName)
	}
}

func TestGetCVESources_NoSources(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9041", "medium", nil)

	sources, err := db.GetCVESources(ctx, "CVE-2024-9041")
	if err != nil {
		t.Fatalf("GetCVESources(no sources): %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("expected nil or empty sources, got %d", len(sources))
	}
}

// ── GetCVESnapshot tests ──────────────────────────────────────────────────────

func TestGetCVESnapshot_HappyPath(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	db.SeedTestCVE(t, "CVE-2024-9051", "critical", &testutil.SeedCVEOpts{
		CvssV3Score:      ptrFloat64(9.1),
		EpssScore:        ptrFloat64(0.85),
		ExploitAvailable: true,
		InCisaKev:        true,
	})

	snap, err := db.GetCVESnapshot(ctx, "CVE-2024-9051")
	if err != nil {
		t.Fatalf("GetCVESnapshot: %v", err)
	}
	if snap == nil {
		t.Fatal("GetCVESnapshot returned nil for existing CVE")
	}
	if snap.CveID != "CVE-2024-9051" {
		t.Errorf("CveID = %q, want CVE-2024-9051", snap.CveID)
	}
	if snap.Severity != (sql.NullString{String: "critical", Valid: true}) {
		t.Errorf("Severity = %v, want critical", snap.Severity)
	}
	if !snap.CvssV3Score.Valid || snap.CvssV3Score.Float64 != 9.1 {
		t.Errorf("CvssV3Score = %v, want 9.1", snap.CvssV3Score)
	}
	if !snap.EpssScore.Valid || snap.EpssScore.Float64 != 0.85 {
		t.Errorf("EpssScore = %v, want 0.85", snap.EpssScore)
	}
	if !snap.ExploitAvailable {
		t.Error("ExploitAvailable should be true")
	}
	if !snap.InCisaKev {
		t.Error("InCisaKev should be true")
	}
}

func TestGetCVESnapshot_NotFound(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	snap, err := db.GetCVESnapshot(ctx, "CVE-0000-0002")
	if err != nil {
		t.Fatalf("GetCVESnapshot(not found): %v", err)
	}
	if snap != nil {
		t.Error("GetCVESnapshot should return nil for non-existent CVE")
	}
}
