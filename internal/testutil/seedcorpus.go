// ABOUTME: Test helper that seeds a test database with curated CVEs from golden fixtures.
// ABOUTME: Runs adapters against fixture files through the real merge pipeline for deterministic data.
package testutil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/feed/kev"
	"github.com/scarson/cvert-ops/internal/feed/mitre"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/feed/osv"
	"github.com/scarson/cvert-ops/internal/feed/redhat"
	"github.com/scarson/cvert-ops/internal/merge"
)

// SeedStats reports what SeedCorpus populated.
type SeedStats struct {
	TotalCVEs   int      // total unique CVEs ingested across all feeds
	FeedsSeeded int      // number of feeds that produced patches
	FeedNames   []string // names of feeds that were seeded
}

// SeedCorpus runs all feed adapters against their golden fixtures through
// the real merge pipeline, producing a deterministic CVE corpus in the test DB.
// EPSS scores are applied last (requires CVE rows to exist).
func SeedCorpus(t *testing.T, db *TestDB) SeedStats {
	t.Helper()

	// Locate the golden fixture root relative to this source file.
	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")

	ctx := context.Background()
	var stats SeedStats
	cvesSeen := make(map[string]bool)

	// Ingestion order matters for merge field precedence (PLAN.md §5.1).
	type feedDef struct {
		name       string
		sourceName string
		fetchFn    func(t *testing.T, projectRoot string) []feed.CanonicalPatch
	}

	feeds := []feedDef{
		{"nvd", "nvd", fetchNVDGolden},
		{"mitre", "mitre", fetchMITREGolden},
		{"ghsa", "ghsa", fetchGHSAGolden},
		{"osv", "osv", fetchOSVGolden},
		{"kev", "kev", fetchKEVGolden},
		{"redhat", "redhat", fetchRedHatGolden},
	}

	for _, fd := range feeds {
		patches := fd.fetchFn(t, projectRoot)
		if len(patches) == 0 {
			t.Logf("SeedCorpus: %s produced 0 patches (known issue or empty fixtures)", fd.name)
			continue
		}

		for _, patch := range patches {
			if err := merge.Ingest(ctx, db.Store, patch, fd.sourceName); err != nil {
				t.Fatalf("SeedCorpus: merge.Ingest %s/%s: %v", fd.name, patch.CVEID, err)
			}
			if patch.CVEID != "" {
				cvesSeen[patch.CVEID] = true
			}
		}

		stats.FeedsSeeded++
		stats.FeedNames = append(stats.FeedNames, fd.name)
		t.Logf("SeedCorpus: %s ingested %d patches", fd.name, len(patches))
	}

	// Apply EPSS last — it needs CVE rows to exist.
	if epssPatches := applyEPSSGolden(t, db, projectRoot); epssPatches > 0 {
		stats.FeedsSeeded++
		stats.FeedNames = append(stats.FeedNames, "epss")
		t.Logf("SeedCorpus: epss applied %d scores", epssPatches)
	}

	stats.TotalCVEs = len(cvesSeen)
	return stats
}

func fetchNVDGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "nvd", "testdata", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("NVD golden fixtures missing: %v", err)
	}

	var pages []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			pages = append(pages, filepath.Join(goldenDir, e.Name()))
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
		data, err := os.ReadFile(pages[idx])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Tue, 11 Mar 2026 10:00:00 GMT")
		w.Write(data)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://services.nvd.nist.gov", srv.URL, http.DefaultTransport),
	}

	t.Setenv("NVD_API_KEY", "golden-test-dummy-key")
	adapter := nvd.New(client)

	initialCursor, _ := json.Marshal(nvd.Cursor{
		WindowStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC),
		StartIndex:  0,
	})

	return fetchAllPatches(t, adapter, json.RawMessage(initialCursor))
}

func fetchMITREGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "mitre", "testdata", "golden")
	zipData, err := os.ReadFile(filepath.Join(goldenDir, "cvelistV5.zip"))
	if err != nil {
		t.Fatalf("MITRE golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://github.com", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, mitre.New(client), nil)
}

func fetchGHSAGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "ghsa", "testdata", "golden")
	pageData, err := os.ReadFile(filepath.Join(goldenDir, "page-001.json"))
	if err != nil {
		t.Fatalf("GHSA golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(pageData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://api.github.com", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, ghsa.New(client), nil)
}

func fetchOSVGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "osv", "testdata", "golden")
	zipData, err := os.ReadFile(filepath.Join(goldenDir, "all.zip"))
	if err != nil {
		t.Fatalf("OSV golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(zipData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://osv-vulnerabilities.storage.googleapis.com", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, osv.New(client), nil)
}

func fetchKEVGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "kev", "testdata", "golden")
	catalogData, err := os.ReadFile(filepath.Join(goldenDir, "catalog.json"))
	if err != nil {
		t.Fatalf("KEV golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(catalogData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://www.cisa.gov", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, kev.New(client), nil)
}

func fetchRedHatGolden(t *testing.T, projectRoot string) []feed.CanonicalPatch {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "redhat", "testdata", "golden")
	listData, err := os.ReadFile(filepath.Join(goldenDir, "list.json"))
	if err != nil {
		t.Fatalf("Red Hat golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path
		if strings.HasSuffix(path, "/cve.json") {
			w.Write(listData)
			return
		}
		if strings.Contains(path, "/cve/CVE-") {
			parts := strings.Split(path, "/")
			if len(parts) > 0 {
				filename := parts[len(parts)-1]
				cveID := strings.TrimSuffix(filename, ".json")
				detailPath := filepath.Join(goldenDir, "detail", cveID+".json")
				data, err := os.ReadFile(detailPath)
				if err != nil {
					http.NotFound(w, r)
					return
				}
				w.Write(data)
				return
			}
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://access.redhat.com", srv.URL, http.DefaultTransport),
	}

	return fetchAllPatches(t, redhat.New(client), nil)
}

func applyEPSSGolden(t *testing.T, db *TestDB, projectRoot string) int {
	t.Helper()
	goldenDir := filepath.Join(projectRoot, "internal", "feed", "epss", "testdata", "golden")
	scoresData, err := os.ReadFile(filepath.Join(goldenDir, "scores.csv.gz"))
	if err != nil {
		t.Logf("EPSS golden fixture missing (skipping): %v", err)
		return 0
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(scoresData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: NewURLRewriteTransport("https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport),
	}

	adapter := epss.New(client)
	cursor, err := adapter.Apply(context.Background(), db.Store.DB(), nil)
	if err != nil {
		t.Fatalf("SeedCorpus: EPSS Apply: %v", err)
	}
	if cursor == nil {
		t.Error("SeedCorpus: EPSS Apply returned nil cursor")
	}

	// Count how many CVEs got EPSS scores.
	var count int
	err = db.Store.DB().QueryRow("SELECT COUNT(*) FROM cves WHERE epss_score IS NOT NULL").Scan(&count)
	if err != nil {
		t.Fatalf("SeedCorpus: count EPSS scores: %v", err)
	}

	return count
}

// fetchAllPatches calls Fetch in a loop until LastPage.
func fetchAllPatches(t *testing.T, adapter feed.Adapter, initialCursor json.RawMessage) []feed.CanonicalPatch {
	t.Helper()
	var all []feed.CanonicalPatch
	cursor := initialCursor
	for {
		result, err := adapter.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("fetchAllPatches: %v", err)
		}
		all = append(all, result.Patches...)
		if result.LastPage {
			break
		}
		cursor = result.NextCursor
	}
	return all
}
