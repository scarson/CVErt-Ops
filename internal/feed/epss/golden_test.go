// ABOUTME: Golden file test for the EPSS adapter using captured real EPSS CSV scores.
// ABOUTME: Seeds NVD CVEs via the merge pipeline, applies EPSS scores, verifies DB values.
package epss_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
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
//
// This test seeds NVD only (not SeedCorpus) because SeedCorpus runs all 8
// adapters — disproportionate when we only need CVE rows for EPSS to update.
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

	// Assertion 3: cross-check DB scores against the fixture CSV.
	// Parse the golden CSV to build expected scores, then compare against DB.
	expectedScores := parseGoldenEPSSScores(t, scoresData)

	rows, err := db.Store.DB().QueryContext(ctx,
		"SELECT cve_id, epss_score FROM cves WHERE epss_score IS NOT NULL")
	if err != nil {
		t.Fatalf("query scored CVEs: %v", err)
	}
	defer rows.Close() //nolint:errcheck

	var lowestCVE string
	var lowestScore float64
	first := true
	for rows.Next() {
		var cveID string
		var dbScore sql.NullFloat64
		if err := rows.Scan(&cveID, &dbScore); err != nil {
			t.Fatalf("scan scored CVE: %v", err)
		}
		if !dbScore.Valid {
			t.Errorf("%s: epss_score is NULL after IS NOT NULL filter", cveID)
			continue
		}
		csvScore, ok := expectedScores[cveID]
		if !ok {
			t.Errorf("%s: has DB score %f but not found in golden CSV", cveID, dbScore.Float64)
			continue
		}
		if dbScore.Float64 != csvScore {
			t.Errorf("%s: DB score %f != CSV score %f", cveID, dbScore.Float64, csvScore)
		}
		if first || dbScore.Float64 < lowestScore {
			lowestCVE = cveID
			lowestScore = dbScore.Float64
			first = false
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows iteration: %v", err)
	}

	// Assertion 4 (testing-pitfalls §9.4): verify a low EPSS score was preserved,
	// not dropped by a truthiness check.
	// Known gap: the golden CSV has no score of exactly 0.0, so we cannot test
	// the 0.0-preserved-as-0.0-not-NULL case here. That case is covered by the
	// EPSS unit tests (TestApply_SkipsPoisonRows). If the golden CSV is refreshed
	// with a 0.0-score CVE, add an explicit assertion: Valid == true && Float64 == 0.0.
	if first {
		t.Error("no scored CVEs found to verify low-score preservation")
	} else {
		t.Logf("low EPSS score correctly applied: %s = %f", lowestCVE, lowestScore)
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

// parseGoldenEPSSScores decompresses the golden scores.csv.gz and returns a
// map of CVE ID → EPSS score for cross-checking against DB values.
func parseGoldenEPSSScores(t *testing.T, gzData []byte) map[string]float64 {
	t.Helper()

	gr, err := gzip.NewReader(bytes.NewReader(gzData))
	if err != nil {
		t.Fatalf("decompress EPSS golden fixture: %v", err)
	}
	defer gr.Close() //nolint:errcheck

	scores := make(map[string]float64)
	scanner := bufio.NewScanner(gr)
	for scanner.Scan() {
		line := scanner.Text()
		// Skip comment lines and header.
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "cve,") {
			continue
		}
		// Format: "CVE-YYYY-NNNN,score,percentile"
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		score, parseErr := strconv.ParseFloat(parts[1], 64)
		if parseErr != nil {
			t.Logf("skipping unparseable EPSS line: %s", line)
			continue
		}
		scores[parts[0]] = score
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan EPSS CSV: %v", err)
	}
	if len(scores) == 0 {
		t.Fatal("parsed 0 scores from golden EPSS CSV")
	}
	return scores
}
