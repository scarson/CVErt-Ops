// ABOUTME: Golden file test for the NVD adapter using captured real API responses.
// ABOUTME: Catches upstream schema drift that hand-crafted test fixtures would miss.
package nvd_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestFetch_GoldenFiles runs the NVD adapter against captured real API responses.
func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	entries, err := os.ReadDir(goldenDir)
	if err != nil {
		t.Fatalf("golden fixtures missing at %s: %v", goldenDir, err)
	}

	// Collect page files, sorted by name.
	var pages []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			pages = append(pages, filepath.Join(goldenDir, e.Name()))
		}
	}
	if len(pages) == 0 {
		t.Fatalf("no .json fixture files in %s", goldenDir)
	}
	sort.Strings(pages)

	// Serve pages sequentially: first fetch → first page, second → second page, etc.
	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		idx := int(requestCount.Add(1)) - 1
		if idx >= len(pages) {
			http.Error(w, "no more fixture pages", http.StatusNotFound)
			return
		}
		data, err := os.ReadFile(pages[idx])
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// The Date header provides effectiveNow for cursor pagination.
		// Must match the cursor's WindowEnd so computeNextCursor returns
		// LastPage=true after the first window.
		w.Header().Set("Date", "Tue, 11 Mar 2026 10:00:00 GMT")
		_, _ = w.Write(data)
	}))
	t.Cleanup(srv.Close)

	// Rewrite NVD API URL to our test server.
	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://services.nvd.nist.gov",
			srv.URL,
			http.DefaultTransport,
		),
	}

	// Set a dummy API key so the adapter uses the faster rate limiter (0.6s/req
	// instead of 6s/req). Golden tests don't hit the real NVD API.
	t.Setenv("NVD_API_KEY", "golden-test-dummy-key")
	adapter := nvd.New(client)

	// Construct a cursor whose window covers a recent range so the adapter
	// finishes in 1 page. Window must be <= 120 days (NVD windowMax).
	// WindowEnd matches the Date header so computeNextCursor returns LastPage=true.
	initialCursor, _ := json.Marshal(nvd.Cursor{
		WindowStart: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		WindowEnd:   time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC),
		StartIndex:  0,
	})

	// Paginate until LastPage, collecting all patches.
	var allPatches []feed.CanonicalPatch
	cursor := json.RawMessage(initialCursor)
	for {
		result, err := adapter.Fetch(context.Background(), cursor)
		if err != nil {
			t.Fatalf("Fetch failed: %v", err)
		}
		allPatches = append(allPatches, result.Patches...)
		if result.LastPage {
			break
		}
		cursor = result.NextCursor
	}

	if len(allPatches) == 0 {
		t.Fatal("expected patches from golden file, got 0")
	}

	// Verify each patch has required fields.
	for i, p := range allPatches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
	}

	t.Logf("parsed %d patches from golden files across %d request(s)",
		len(allPatches), requestCount.Load())
}
