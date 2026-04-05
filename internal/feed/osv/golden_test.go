// ABOUTME: Golden file test for the OSV adapter using a curated all.zip subset.
// ABOUTME: Verifies ZIP-based bulk parsing and alias resolution (non-CVE → CVE).
package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed/osv"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	zipData, err := os.ReadFile(filepath.Join(goldenDir, "all.zip"))
	if err != nil {
		t.Fatalf("golden fixture missing: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://osv-vulnerabilities.storage.googleapis.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := osv.New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if !result.LastPage {
		t.Error("OSV should always return LastPage=true")
	}

	if len(result.Patches) == 0 {
		t.Fatal("expected non-zero patches from golden OSV ZIP")
	}

	// Verify: at least one patch has alias resolution (non-CVE SourceID, CVE in CVEID).
	var hasAliasResolution bool
	for _, p := range result.Patches {
		if p.CVEID != "" && p.SourceID != "" && !strings.HasPrefix(p.SourceID, "CVE-") {
			hasAliasResolution = true
			break
		}
	}
	if !hasAliasResolution {
		t.Error("expected at least one patch with alias resolution (non-CVE SourceID → CVE CVEID)")
	}

	t.Logf("parsed %d OSV patches from golden ZIP", len(result.Patches))
}
