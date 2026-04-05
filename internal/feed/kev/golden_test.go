// ABOUTME: Golden file test for the KEV adapter using captured real CISA catalog.
// ABOUTME: Catches upstream schema drift and verifies KEV-specific patch fields.
package kev_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed/kev"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestFetch_GoldenFiles(t *testing.T) {
	goldenDir := filepath.Join("testdata", "golden")
	if _, err := os.Stat(filepath.Join(goldenDir, "catalog.json")); err != nil {
		t.Fatalf("golden fixture missing: %v", err)
	}

	catalogData, err := os.ReadFile(filepath.Join(goldenDir, "catalog.json"))
	if err != nil {
		t.Fatalf("read catalog fixture: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(catalogData)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport(
			"https://www.cisa.gov",
			srv.URL,
			http.DefaultTransport,
		),
	}

	adapter := kev.New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if !result.LastPage {
		t.Error("KEV should always return LastPage=true")
	}

	if len(result.Patches) == 0 {
		t.Fatal("expected non-zero patches from golden catalog")
	}

	// Verify KEV-specific fields on every patch.
	for i, p := range result.Patches {
		if p.CVEID == "" {
			t.Errorf("patch[%d]: empty CVEID", i)
		}
		if p.InCISAKEV == nil || !*p.InCISAKEV {
			t.Errorf("patch[%d] (%s): InCISAKEV should be true (got nil=%v)", i, p.CVEID, p.InCISAKEV == nil)
		}
		if p.VendorEnrichment == nil {
			t.Errorf("patch[%d] (%s): VendorEnrichment should be non-nil", i, p.CVEID)
		} else if len(p.VendorEnrichment.Data) == 0 {
			t.Errorf("patch[%d] (%s): VendorEnrichment.Data should be non-empty", i, p.CVEID)
		}
	}

	t.Logf("parsed %d KEV patches from golden catalog", len(result.Patches))
}
