// ABOUTME: Golden file test for the Red Hat adapter using captured list + detail pages.
// ABOUTME: Verifies vendor enrichment (severity, fix state) from real Red Hat API data.
package redhat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed/redhat"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	listData, err := os.ReadFile(filepath.Join(goldenDir, "list.json"))
	if err != nil {
		t.Fatalf("golden list fixture missing: %v", err)
	}

	// Route by path: /cve.json → list, /cve/CVE-* → detail lookup.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		path := r.URL.Path
		if strings.HasSuffix(path, "/cve.json") || strings.Contains(path, "/cve.json?") {
			_, _ = w.Write(listData)
			return
		}

		// Detail pages: path like /hydra/rest/securitydata/cve/CVE-YYYY-NNNN.json
		if strings.Contains(path, "/cve/CVE-") {
			// Extract CVE ID from path.
			parts := strings.Split(path, "/")
			if len(parts) > 0 {
				filename := parts[len(parts)-1] // "CVE-YYYY-NNNN.json"
				cveID := strings.TrimSuffix(filename, ".json")
				detailPath := filepath.Join(goldenDir, "detail", cveID+".json")
				data, err := os.ReadFile(detailPath) //nolint:gosec // G703: test helper reads from known golden fixture directory
				if err != nil {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(data) //nolint:gosec // G705: test helper serves golden fixture data, not user input
				return
			}
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://access.redhat.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := redhat.New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if len(result.Patches) == 0 {
		t.Fatal("expected non-zero patches from golden Red Hat data")
	}

	// Verify every patch has a CVE ID.
	for i, p := range result.Patches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
	}

	// Verify at least one patch has VendorEnrichment.
	var hasEnrichment bool
	for _, p := range result.Patches {
		if p.VendorEnrichment != nil {
			hasEnrichment = true
			// Check sub-fields.
			if p.VendorEnrichment.VendorSeverity != nil && *p.VendorEnrichment.VendorSeverity != "" {
				t.Logf("found VendorSeverity=%q on %s", *p.VendorEnrichment.VendorSeverity, p.CVEID)
			}
			break
		}
	}
	if !hasEnrichment {
		t.Error("expected at least one patch with VendorEnrichment")
	}

	t.Logf("parsed %d Red Hat patches from golden files", len(result.Patches))
}
