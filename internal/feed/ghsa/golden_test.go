// ABOUTME: Golden file test for the GHSA adapter using captured real GitHub Advisory responses.
// ABOUTME: Catches upstream schema drift, verifies alias resolution for null-CVE advisories.
package ghsa_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed/ghsa"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	pageData, err := os.ReadFile(filepath.Join(goldenDir, "page-001.json"))
	if err != nil {
		t.Fatalf("golden fixture missing: %v", err)
	}

	// GHSA adapter expects JSON array, no Link header = last page.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No Link header → adapter sees no "next" cursor → LastPage=true.
		_, _ = w.Write(pageData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://api.github.com",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := ghsa.New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if !result.LastPage {
		t.Error("expected LastPage=true (no Link header)")
	}

	if len(result.Patches) == 0 {
		t.Fatal("expected non-zero patches from golden GHSA data")
	}

	// Verify: at least one patch has a CVE ID (mapped advisory).
	var hasCVE bool
	// Verify: at least one patch has a GHSA-native ID (no CVE mapping, category F1).
	// ResolveCanonicalID returns the native GHSA ID when no CVE alias exists,
	// so CVEID will be the GHSA ID — not empty.
	var hasGHSANative bool
	for _, p := range result.Patches {
		if strings.HasPrefix(p.CVEID, "CVE-") {
			hasCVE = true
		}
		if strings.HasPrefix(p.CVEID, "GHSA-") {
			hasGHSANative = true
		}
	}
	if !hasCVE {
		t.Error("expected at least one patch with CVE ID")
	}
	if !hasGHSANative {
		t.Error("expected at least one GHSA-native patch (CVEID starts with GHSA-)")
	}

	// Verify all patches have a SourceID.
	for i, p := range result.Patches {
		if p.SourceID == "" {
			t.Errorf("patch[%d]: empty SourceID", i)
		}
	}

	t.Logf("parsed %d GHSA patches from golden files", len(result.Patches))
}
