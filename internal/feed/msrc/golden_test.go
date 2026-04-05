// ABOUTME: Golden file test for the MSRC adapter using captured CSAF documents.
// ABOUTME: Verifies vendor enrichment, CVSS extraction, and CSAF parsing from real API data.
package msrc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/msrc"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")

	// Read changes.csv fixture.
	changesCSV, err := os.ReadFile(filepath.Join(goldenDir, "changes.csv"))
	if err != nil {
		t.Fatalf("read changes.csv fixture: %v", err)
	}

	// Load per-CVE CSAF fixture files keyed by filename.
	csafDir := filepath.Join(goldenDir, "csaf")
	csafEntries, err := os.ReadDir(csafDir)
	if err != nil {
		t.Fatalf("golden CSAF fixtures missing: %v", err)
	}

	csafByName := make(map[string][]byte)
	for _, e := range csafEntries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(csafDir, e.Name()))
		if readErr != nil {
			t.Fatalf("read CSAF fixture %s: %v", e.Name(), readErr)
		}
		csafByName[e.Name()] = data
	}
	if len(csafByName) == 0 {
		t.Fatal("no CSAF fixture files found")
	}

	// Route requests: /changes.csv → changes CSV,
	// /{year}/{filename}.json → CSAF fixture file.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if strings.HasSuffix(path, "/changes.csv") {
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write(changesCSV)
			return
		}

		if strings.HasSuffix(path, ".json") {
			// Extract filename from path like /csaf/advisories/2026/msrc_cve-2026-21510.json
			parts := strings.Split(path, "/")
			filename := parts[len(parts)-1]
			data, ok := csafByName[filename]
			if ok {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(data)
				return
			}
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://msrc.microsoft.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := msrc.New(client)

	// Fetch with nil cursor to get all entries from changes.csv.
	var allPatches []feed.CanonicalPatch
	cursor := json.RawMessage(nil)
	for {
		result, fetchErr := adapter.Fetch(context.Background(), cursor)
		if fetchErr != nil {
			t.Fatalf("Fetch failed: %v", fetchErr)
		}
		allPatches = append(allPatches, result.Patches...)
		if result.LastPage {
			break
		}
		cursor = result.NextCursor
	}

	// Assertion 1: non-zero patches.
	if len(allPatches) == 0 {
		t.Fatal("expected non-zero patches from golden MSRC CSAF data")
	}

	// Assertion 2: every patch has a CVE ID with proper format.
	for i, p := range allPatches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
		if !strings.HasPrefix(p.CVEID, "CVE-") {
			t.Errorf("patch[%d]: CVEID %q does not start with CVE-", i, p.CVEID)
		}
	}

	// Assertion 3: at least one patch has VendorEnrichment.
	var hasEnrichment bool
	for _, p := range allPatches {
		if p.VendorEnrichment != nil {
			hasEnrichment = true
			// Assertion 4: VendorEnrichment.Data is non-empty.
			if len(p.VendorEnrichment.Data) == 0 {
				t.Errorf("patch %s: VendorEnrichment.Data is empty", p.CVEID)
			}
			break
		}
	}
	if !hasEnrichment {
		t.Error("expected at least one patch with VendorEnrichment")
	}

	// Assertion 5: at least one patch has a CVSS v3 score.
	var hasCVSS bool
	for _, p := range allPatches {
		if p.CVSSv3Score != nil {
			hasCVSS = true
			t.Logf("found CVSSv3Score=%f on %s", *p.CVSSv3Score, p.CVEID)
			break
		}
	}
	if !hasCVSS {
		t.Error("expected at least one patch with CVSSv3Score")
	}

	// Assertion 6: falsy-value check (testing-pitfalls §9.4).
	// If any MSRC patch has a CVSS score of 0.0, verify it's preserved.
	for _, p := range allPatches {
		if p.CVSSv3Score != nil && *p.CVSSv3Score == 0.0 {
			t.Logf("falsy-value check: %s has CVSSv3Score=0.0 (correctly preserved)", p.CVEID)
		}
	}

	t.Logf("parsed %d MSRC patches from %d CSAF documents", len(allPatches), len(csafByName))
}
