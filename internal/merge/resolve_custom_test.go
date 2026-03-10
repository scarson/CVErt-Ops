// ABOUTME: Tests verifying custom (non-built-in) source precedence in the merge resolver.
// ABOUTME: Ensures custom sources lose scalar precedence to built-in sources but contribute to unions.
package merge

import (
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

func TestResolve_CustomSourceCVSSLosesToNVD(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{CVEID: "CVE-2025-9001", CVSSv3Score: f64Ptr(7.5)}),
		makeSource("internal-scanner", feed.CanonicalPatch{CVEID: "CVE-2025-9001", CVSSv3Score: f64Ptr(8.0)}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.CVSSv3Score == nil || *r.CVSSv3Score != 7.5 {
		t.Errorf("CVSSv3Score = %v, want 7.5 (NVD should win over custom source)", r.CVSSv3Score)
	}
	if r.CVSSv3Source != SourceNVD {
		t.Errorf("CVSSv3Source = %q, want %q", r.CVSSv3Source, SourceNVD)
	}
}

func TestResolve_CustomSourceOnlySource(t *testing.T) {
	t.Parallel()

	desc := "Custom scanner found this vulnerability"
	sources := []generated.CveSource{
		makeSource("internal-scanner", feed.CanonicalPatch{
			CVEID:              "CVE-2025-9002",
			Status:             "Confirmed",
			DescriptionPrimary: &desc,
			CVSSv3Score:        f64Ptr(6.5),
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Status != "Confirmed" {
		t.Errorf("Status = %q, want %q", r.Status, "Confirmed")
	}
	if r.DescriptionPrimary == nil || *r.DescriptionPrimary != desc {
		t.Errorf("DescriptionPrimary = %v, want %q", r.DescriptionPrimary, desc)
	}
	if r.CVSSv3Score == nil || *r.CVSSv3Score != 6.5 {
		t.Errorf("CVSSv3Score = %v, want 6.5", r.CVSSv3Score)
	}
	if r.CVSSv3Source != "internal-scanner" {
		t.Errorf("CVSSv3Source = %q, want %q", r.CVSSv3Source, "internal-scanner")
	}
}

func TestResolve_CustomSourceReferencesInUnion(t *testing.T) {
	t.Parallel()

	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{
			CVEID:      "CVE-2025-9003",
			References: []feed.ReferenceEntry{{URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-9003"}},
		}),
		makeSource("internal-scanner", feed.CanonicalPatch{
			CVEID:      "CVE-2025-9003",
			References: []feed.ReferenceEntry{{URL: "https://internal.example.com/findings/9003"}},
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(r.References) != 2 {
		t.Fatalf("References count = %d, want 2 (union of NVD + custom)", len(r.References))
	}
	urls := map[string]bool{}
	for _, ref := range r.References {
		urls[ref.URL] = true
	}
	if !urls["https://nvd.nist.gov/vuln/detail/CVE-2025-9003"] {
		t.Error("missing NVD reference in union")
	}
	if !urls["https://internal.example.com/findings/9003"] {
		t.Error("missing custom source reference in union")
	}
}

func TestResolve_CustomSourcePackagesInUnion(t *testing.T) {
	t.Parallel()

	nvdPkg := feed.AffectedPackage{
		Ecosystem: "npm", PackageName: "lodash", Introduced: "4.0.0", Fixed: "4.17.21",
	}
	customPkg := feed.AffectedPackage{
		Ecosystem: "npm", PackageName: "express", Introduced: "4.0.0", Fixed: "4.18.2",
	}
	// Same package as NVD but from custom source (different Fixed version).
	customDupPkg := feed.AffectedPackage{
		Ecosystem: "npm", PackageName: "lodash", Introduced: "4.0.0", Fixed: "4.17.20",
	}
	sources := []generated.CveSource{
		makeSource(SourceNVD, feed.CanonicalPatch{
			CVEID:            "CVE-2025-9004",
			AffectedPackages: []feed.AffectedPackage{nvdPkg},
		}),
		makeSource("internal-scanner", feed.CanonicalPatch{
			CVEID:            "CVE-2025-9004",
			AffectedPackages: []feed.AffectedPackage{customPkg, customDupPkg},
		}),
	}
	r, err := resolve(sources)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Expect 2 packages: lodash (from NVD, wins dedup) and express (unique from custom).
	if len(r.AffectedPackages) != 2 {
		t.Fatalf("AffectedPackages count = %d, want 2", len(r.AffectedPackages))
	}

	pkgMap := map[string]feed.AffectedPackage{}
	for _, pkg := range r.AffectedPackages {
		pkgMap[pkg.PackageName] = pkg
	}

	// NVD wins the lodash dedup because NVD is higher in pkgPriority than custom.
	lodash, ok := pkgMap["lodash"]
	if !ok {
		t.Fatal("missing lodash in AffectedPackages")
	}
	if lodash.Fixed != "4.17.21" {
		t.Errorf("lodash.Fixed = %q, want %q (NVD should win over custom source)", lodash.Fixed, "4.17.21")
	}

	// express is unique to custom source, so it should be present.
	if _, ok := pkgMap["express"]; !ok {
		t.Error("missing express in AffectedPackages (custom source unique package)")
	}
}
