// ABOUTME: Golden file test for the MITRE adapter using a curated cvelistV5 ZIP subset.
// ABOUTME: Verifies ZIP-based bulk parsing and detects upstream schema drift.
package mitre_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/mitre"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// goldenPatch returns the patch the adapter builds for one CVE in the golden ZIP.
func goldenPatch(t *testing.T, cveID string) feed.CanonicalPatch {
	t.Helper()
	result := fetchGolden(t)
	for _, p := range result.Patches {
		if p.CVEID == cveID {
			return p
		}
	}
	t.Fatalf("%s missing from golden ZIP", cveID)
	return feed.CanonicalPatch{}
}

// CVE-2026-107832 has no NVD configurations, so this is all CVErt Ops knows about it.
func TestFetch_GoldenCNAAffected_NotYetAnalysedByNVD(t *testing.T) {
	p := goldenPatch(t, "CVE-2026-107832")

	want := []feed.CNAAffected{{
		Vendor:        "fastify",
		Product:       "fastify",
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

func TestFetch_GoldenCNAAffected_LessThanOrEqual(t *testing.T) {
	p := goldenPatch(t, "CVE-2026-56847")

	want := []feed.CNAAffected{{
		Vendor:        "nodejs",
		Product:       "node",
		DefaultStatus: "unaffected",
		Versions: []feed.CNAVersion{
			{Version: "26.5.0", LessThanOrEqual: "26.5.0", Status: "affected", VersionType: "semver"},
			{Version: "24.18.0", LessThanOrEqual: "24.18.0", Status: "affected", VersionType: "semver"},
			{Version: "22.23.1", LessThanOrEqual: "22.23.1", Status: "affected", VersionType: "semver"},
		},
	}}
	if !reflect.DeepEqual(p.CNAAffected, want) {
		t.Errorf("CNAAffected = %+v, want %+v", p.CNAAffected, want)
	}
}

// The Linux kernel CNA lists one product twice, and states both affected and
// unaffected versions under opposite default statuses.
func TestFetch_GoldenCNAAffected_KeepsEntriesAndUnaffectedVersions(t *testing.T) {
	p := goldenPatch(t, "CVE-2025-40110")

	if len(p.CNAAffected) != 2 {
		t.Fatalf("CNAAffected has %d entries, want 2: %+v", len(p.CNAAffected), p.CNAAffected)
	}
	if got := p.CNAAffected[0]; got.Vendor != "Linux" || got.Product != "Linux" || got.DefaultStatus != "unaffected" {
		t.Errorf("entry 0 = %s/%s default %s, want Linux/Linux default unaffected", got.Vendor, got.Product, got.DefaultStatus)
	}
	if got := p.CNAAffected[1]; got.DefaultStatus != "affected" {
		t.Errorf("entry 1 default = %s, want affected", got.DefaultStatus)
	}
	hasUnaffected := slices.ContainsFunc(p.CNAAffected[1].Versions, func(v feed.CNAVersion) bool { return v.Status == "unaffected" })
	if !hasUnaffected {
		t.Errorf("entry 1 lost its unaffected versions: %+v", p.CNAAffected[1].Versions)
	}
}

func TestFetch_GoldenCNAAffected_KeepsVersionChanges(t *testing.T) {
	p := goldenPatch(t, "CVE-2021-44228")

	found := false
	for _, a := range p.CNAAffected {
		for _, v := range a.Versions {
			if len(v.Changes) > 0 {
				found = v.Changes[0].At != "" && v.Changes[0].Status != ""
			}
		}
	}
	if !found {
		t.Errorf("no versions[].changes survived: %+v", p.CNAAffected)
	}
}

func TestFetch_GoldenFiles(t *testing.T) {
	result := fetchGolden(t)

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

// fetchGolden serves the curated cvelistV5 ZIP through a test server and runs the adapter over it.
func fetchGolden(t *testing.T) *feed.FetchResult {
	t.Helper()
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
	return result
}
