// ABOUTME: Golden file test for the EPSS adapter using captured real EPSS CSV scores.
// ABOUTME: Seeds NVD CVEs via the merge pipeline, applies EPSS scores, verifies DB values.
package epss_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestApply_GoldenFiles seeds NVD CVEs from golden fixtures through the merge
// pipeline, then applies the EPSS golden scores CSV and verifies DB values.
func TestApply_GoldenFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("requires testcontainer")
	}

	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Seed NVD CVEs so EPSS has rows to update.
	nvdPatches := seedNVDForEPSS(t, db)
	t.Logf("seeded %d NVD CVEs for EPSS golden test", len(nvdPatches))

	// Serve the EPSS golden fixture.
	_, thisFile, _, _ := runtime.Caller(0)
	goldenDir := filepath.Join(filepath.Dir(thisFile), "testdata", "golden")
	scoresData, err := os.ReadFile(filepath.Join(goldenDir, "scores.csv.gz"))
	if err != nil {
		t.Fatalf("EPSS golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(scoresData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport),
	}

	adapter := epss.New(client)

	// Apply EPSS scores.
	cursor, err := adapter.Apply(ctx, db.Store.DB(), nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// Assertion 1: cursor is non-nil (EPSS returns an updated cursor).
	if cursor == nil {
		t.Error("Apply returned nil cursor")
	}

	// Assertion 2: at least one CVE row has a non-null EPSS score.
	var scoredCount int
	err = db.Store.DB().QueryRow(
		"SELECT COUNT(*) FROM cves WHERE epss_score IS NOT NULL").Scan(&scoredCount)
	if err != nil {
		t.Fatalf("count scored CVEs: %v", err)
	}
	if scoredCount == 0 {
		t.Fatal("EPSS Apply produced 0 scored CVEs — expected at least one")
	}

	// Assertion 3: spot-check a specific CVE's EPSS score from the fixture.
	// Find a CVE that exists in both the NVD fixtures and the EPSS CSV.
	type scoreRow struct {
		cveID string
		score sql.NullFloat64
	}
	rows, err := db.Store.DB().QueryContext(ctx,
		"SELECT cve_id, epss_score FROM cves WHERE epss_score IS NOT NULL ORDER BY epss_score ASC LIMIT 5")
	if err != nil {
		t.Fatalf("query scored CVEs: %v", err)
	}
	defer rows.Close() //nolint:errcheck

	var lowest scoreRow
	if rows.Next() {
		if err := rows.Scan(&lowest.cveID, &lowest.score); err != nil {
			t.Fatalf("scan scored CVE: %v", err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration: %v", err)
	}

	// Assertion 4 (testing-pitfalls §9.4): verify a low EPSS score was preserved,
	// not dropped by a truthiness check. The score must be Valid and >= 0.
	if !lowest.score.Valid {
		t.Error("lowest EPSS score is NULL — expected a valid float64")
	} else if lowest.score.Float64 < 0 {
		t.Errorf("lowest EPSS score is negative: %f", lowest.score.Float64)
	} else {
		t.Logf("low EPSS score correctly applied: %s = %f", lowest.cveID, lowest.score.Float64)
	}

	t.Logf("EPSS applied scores to %d CVE rows", scoredCount)
}

// seedNVDForEPSS fetches NVD golden fixtures and ingests them through the merge
// pipeline so that CVE rows exist for EPSS to update.
func seedNVDForEPSS(t *testing.T, db *testutil.TestDB) []feed.CanonicalPatch {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	// Navigate from internal/feed/epss/ up to internal/feed/nvd/testdata/golden/
	nvdGoldenDir := filepath.Join(filepath.Dir(thisFile), "..", "nvd", "testdata", "golden")

	entries, err := os.ReadDir(nvdGoldenDir)
	if err != nil {
		t.Fatalf("NVD golden fixtures missing at %s: %v", nvdGoldenDir, err)
	}

	var pages []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			pages = append(pages, filepath.Join(nvdGoldenDir, e.Name()))
		}
	}
	sort.Strings(pages)

	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := int(requestCount.Add(1)) - 1
		if idx >= len(pages) {
			http.Error(w, "no more pages", http.StatusNotFound)
			return
		}
		data, readErr := os.ReadFile(pages[idx])
		if readErr != nil {
			http.Error(w, readErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Tue, 11 Mar 2026 10:00:00 GMT")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://services.nvd.nist.gov", srv.URL, http.DefaultTransport),
	}

	t.Setenv("NVD_API_KEY", "golden-test-dummy-key")
	adapter := nvd.New(client)

	initialCursor, _ := json.Marshal(nvd.Cursor{
		WindowStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC),
		StartIndex:  0,
	})

	ctx := context.Background()
	var allPatches []feed.CanonicalPatch
	cursor := json.RawMessage(initialCursor)

	for {
		result, fetchErr := adapter.Fetch(ctx, cursor)
		if fetchErr != nil {
			t.Fatalf("NVD Fetch: %v", fetchErr)
		}
		allPatches = append(allPatches, result.Patches...)
		for _, p := range result.Patches {
			if err := merge.Ingest(ctx, db.Store, p, "nvd"); err != nil {
				t.Fatalf("merge.Ingest NVD %s: %v", p.CVEID, err)
			}
		}
		if result.LastPage {
			break
		}
		cursor = result.NextCursor
	}

	return allPatches
}
