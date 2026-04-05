// ABOUTME: Golden file test for the MITRE adapter using a curated cvelistV5 ZIP subset.
// ABOUTME: Verifies ZIP-based bulk parsing and detects upstream schema drift.
package mitre_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed/mitre"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	zipData, err := os.ReadFile(filepath.Join(goldenDir, "cvelistV5.zip"))
	if err != nil {
		t.Fatalf("golden fixture missing: %v", err)
	}

	// Serve the ZIP file for any request.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://github.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := mitre.New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if !result.LastPage {
		t.Error("MITRE should always return LastPage=true")
	}

	if len(result.Patches) == 0 {
		t.Fatal("expected non-zero patches from golden MITRE ZIP")
	}

	// Verify every patch has a CVE ID.
	for i, p := range result.Patches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
	}

	t.Logf("parsed %d MITRE patches from golden ZIP", len(result.Patches))
}
