// ABOUTME: Golden file test for the NVD adapter using captured real API responses.
// ABOUTME: Catches upstream schema drift that hand-crafted test fixtures would miss.
package nvd_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/nvd"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// goldenPatches returns the patches the adapter builds from the captured responses, keyed by CVE ID.
func goldenPatches(t *testing.T) map[string]feed.CanonicalPatch {
	t.Helper()
	patches, _ := fetchGolden(t)
	byID := make(map[string]feed.CanonicalPatch, len(patches))
	for _, p := range patches {
		byID[p.CVEID] = p
	}
	return byID
}

// nodeJSCriteria is the real criteria string NVD uses for Node.js itself.
const nodeJSCriteria = "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*"

func TestFetch_GoldenCPEMatches_OneCriteriaKeepsEveryBranchRange(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-56847"]

	want := []feed.CPEMatch{
		{CPE: nodeJSCriteria, CPENormalized: nodeJSCriteria, VersionStartIncluding: "22.0", VersionEndIncluding: "22.23.1", Vulnerable: true},
		{CPE: nodeJSCriteria, CPENormalized: nodeJSCriteria, VersionStartIncluding: "24.0.0", VersionEndIncluding: "24.18.0", Vulnerable: true},
		{CPE: nodeJSCriteria, CPENormalized: nodeJSCriteria, VersionStartIncluding: "26.0.0", VersionEndIncluding: "26.5.0", Vulnerable: true},
	}
	if !slices.Equal(p.CPEMatches, want) {
		t.Errorf("CPEMatches = %+v, want %+v", p.CPEMatches, want)
	}
	if len(p.AffectedCPEs) != 1 || p.AffectedCPEs[0].CPENormalized != nodeJSCriteria {
		t.Errorf("AffectedCPEs = %+v, want the one criteria string", p.AffectedCPEs)
	}
}

func TestFetch_GoldenCPEMatches_VersionEndExcluding(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-111497"]

	want := feed.CPEMatch{
		CPE:                   nodeJSCriteria,
		CPENormalized:         nodeJSCriteria,
		VersionStartIncluding: "23.0.0",
		VersionEndExcluding:   "24.22.1",
		Vulnerable:            true,
	}
	if !slices.Contains(p.CPEMatches, want) {
		t.Errorf("CPEMatches missing %+v; got %+v", want, p.CPEMatches)
	}
}

// A firmware CVE names its hardware as vulnerable: false. The hardware stays in
// AffectedCPEs, which is a material_hash input and what CPE watchlist items match.
func TestFetch_GoldenCPEMatches_RunningOnPlatformKeepsItsFlag(t *testing.T) {
	p := goldenPatches(t)["CVE-2017-12542"]

	const (
		firmware = "cpe:2.3:o:hp:integrated_lights-out_4_firmware:*:*:*:*:*:*:*:*"
		hardware = "cpe:2.3:h:hp:integrated_lights-out_4:-:*:*:*:*:*:*:*"
	)
	want := []feed.CPEMatch{
		{CPE: firmware, CPENormalized: firmware, VersionEndExcluding: "2.53", Vulnerable: true},
		{CPE: hardware, CPENormalized: hardware, Vulnerable: false},
	}
	if !slices.Equal(p.CPEMatches, want) {
		t.Errorf("CPEMatches = %+v, want %+v", p.CPEMatches, want)
	}
	if !slices.ContainsFunc(p.AffectedCPEs, func(c feed.AffectedCPE) bool { return c.CPENormalized == hardware }) {
		t.Errorf("AffectedCPEs dropped the vulnerable: false hardware CPE: %+v", p.AffectedCPEs)
	}
}

func TestFetch_GoldenCPEMatches_NotYetAnalysedHasNone(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-107832"]

	if p.CVEID == "" {
		t.Fatal("CVE-2026-107832 missing from golden page")
	}
	if len(p.CPEMatches) != 0 {
		t.Errorf("CPEMatches = %+v, want none before NVD analysis", p.CPEMatches)
	}
}

// NVD relays the CNA's affected[] before it analyses a CVE.
func TestFetch_GoldenCNAAffected_RelayedBeforeAnalysis(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-107832"]

	want := []feed.CNAAffected{{
		Vendor:        "fastify",
		Product:       "fastify",
		PackageKey:    "npm/fastify",
		DefaultStatus: "unaffected",
		Versions: []feed.CNAVersion{
			{Version: "5.12.2", LessThan: "5.12.6", Status: "affected", VersionType: "semver"},
			{Version: "5.12.6", Status: "unaffected", VersionType: "semver"},
		},
	}}
	if !reflect.DeepEqual(p.CNAAffected, want) {
		t.Errorf("CNAAffected = %+v, want %+v", p.CNAAffected, want)
	}
}

// cve.affected[] also holds other organisations' data. Only the entry from the
// CVE's own sourceIdentifier is the CNA's: here Google's, not Siemens's.
func TestFetch_GoldenCNAAffected_OnlyFromTheCVEsOwnCNA(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-111497"]

	if len(p.CNAAffected) != 1 || p.CNAAffected[0].Vendor != "Google" || p.CNAAffected[0].Product != "Brotli" {
		t.Errorf("CNAAffected = %+v, want only Google Brotli", p.CNAAffected)
	}
}

// The raw payload is re-marshalled from the adapter's types, so it keeps a range
// only if those types decode it.
func TestFetch_GoldenRawPayloadKeepsRanges(t *testing.T) {
	p := goldenPatches(t)["CVE-2026-111497"]

	if !bytes.Contains(p.RawPayload, []byte(`"versionEndExcluding":"24.22.1"`)) {
		t.Error("RawPayload lost versionEndExcluding")
	}
}

// TestFetch_GoldenFiles runs the NVD adapter against captured real API responses.
func TestFetch_GoldenFiles(t *testing.T) {
	allPatches, requests := fetchGolden(t)

	if len(allPatches) == 0 {
		t.Fatal("expected patches from golden file, got 0")
	}

	// Verify each patch has required fields.
	for i, p := range allPatches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
	}

	t.Logf("parsed %d patches from golden files across %d request(s)", len(allPatches), requests)
}

// fetchGolden serves the captured pages through a test server and returns every
// patch the adapter builds from them, plus the number of requests it made.
func fetchGolden(t *testing.T) ([]feed.CanonicalPatch, int64) {
	t.Helper()
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

	return allPatches, requestCount.Load()
}
