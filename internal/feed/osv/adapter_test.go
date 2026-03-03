// ABOUTME: Unit tests for OSV feed adapter pure parse/convert functions.
// ABOUTME: Covers isAdvisoryEntry, parseAdvisory, and extractPackageRange.
package osv

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestIsAdvisoryEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		input string
		want bool
	}{
		{"json suffix", "Go/GHSA-abc-123.json", true},
		{"txt suffix", "Go/GHSA-abc-123.txt", false},
		{"no suffix", "Go/GHSA-abc-123", false},
		{"empty string", "", false},
		{"bare json suffix", ".json", true},
		{"json in middle", "file.json.bak", false},
		{"directory only", "Go/", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isAdvisoryEntry(tc.input)
			if got != tc.want {
				t.Errorf("isAdvisoryEntry(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseAdvisory(t *testing.T) {
	t.Parallel()

	t.Run("normal advisory with CVE alias", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:        "GHSA-xxxx-yyyy-zzzz",
			Aliases:   []string{"CVE-2024-12345"},
			Published: "2024-01-15T10:00:00Z",
			Modified:  "2024-01-16T12:00:00Z",
			Details:   "A critical vulnerability in foo.",
			Summary:   "Short summary",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "CVE-2024-12345" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-12345")
		}
		if patch.SourceID != "GHSA-xxxx-yyyy-zzzz" {
			t.Errorf("SourceID = %q, want %q", patch.SourceID, "GHSA-xxxx-yyyy-zzzz")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "A critical vulnerability in foo." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "A critical vulnerability in foo.")
		}
		if patch.DatePublished == nil {
			t.Error("DatePublished is nil, expected non-nil")
		}
		if patch.DateModified == nil {
			t.Error("DateModified is nil, expected non-nil")
		}
	})

	t.Run("no aliases uses native ID", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:      "RUSTSEC-2024-0001",
			Summary: "A rust advisory",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "RUSTSEC-2024-0001" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "RUSTSEC-2024-0001")
		}
		if patch.SourceID != "RUSTSEC-2024-0001" {
			t.Errorf("SourceID = %q, want %q", patch.SourceID, "RUSTSEC-2024-0001")
		}
	})

	t.Run("aliases without CVE uses native ID", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:      "PYSEC-2024-55",
			Aliases: []string{"GHSA-xxxx-yyyy-zzzz", "DSA-1234"},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "PYSEC-2024-55" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "PYSEC-2024-55")
		}
	})

	t.Run("withdrawn advisory", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:        "GHSA-aaaa-bbbb-cccc",
			Withdrawn: "2024-02-01T00:00:00Z",
			Summary:   "This was withdrawn.",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if !patch.IsWithdrawn {
			t.Error("IsWithdrawn = false, want true")
		}
		if patch.Status != "withdrawn" {
			t.Errorf("Status = %q, want %q", patch.Status, "withdrawn")
		}
	})

	t.Run("details preferred over summary", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:      "GHSA-dddd-eeee-ffff",
			Details: "Long detailed description.",
			Summary: "Short summary.",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Long detailed description." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "Long detailed description.")
		}
	})

	t.Run("summary used when details empty", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:      "GHSA-1111-2222-3333",
			Details: "",
			Summary: "Fallback summary.",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Fallback summary." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "Fallback summary.")
		}
	})

	t.Run("affected packages with ranges", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-pkg-test-0001",
			Affected: []osvAffected{
				{
					Package: osvPackage{Ecosystem: "Go", Name: "stdlib"},
					Ranges: []osvRange{
						{
							Type:   "SEMVER",
							Events: json.RawMessage(`[{"introduced":"1.0.0"},{"fixed":"1.2.3"}]`),
						},
					},
				},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.AffectedPackages) != 1 {
			t.Fatalf("AffectedPackages len = %d, want 1", len(patch.AffectedPackages))
		}
		pkg := patch.AffectedPackages[0]
		if pkg.Ecosystem != "Go" {
			t.Errorf("Ecosystem = %q, want %q", pkg.Ecosystem, "Go")
		}
		if pkg.PackageName != "stdlib" {
			t.Errorf("PackageName = %q, want %q", pkg.PackageName, "stdlib")
		}
		if pkg.RangeType != "SEMVER" {
			t.Errorf("RangeType = %q, want %q", pkg.RangeType, "SEMVER")
		}
		if pkg.Introduced != "1.0.0" {
			t.Errorf("Introduced = %q, want %q", pkg.Introduced, "1.0.0")
		}
		if pkg.Fixed != "1.2.3" {
			t.Errorf("Fixed = %q, want %q", pkg.Fixed, "1.2.3")
		}
	})

	t.Run("CVSS vectors stored", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-cvss-test-0001",
			Severity: []osvSeverity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVSSv3Vector == nil {
			t.Fatal("CVSSv3Vector is nil")
		}
		if *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Errorf("CVSSv3Vector = %q, want CVSS:3.1/...", *patch.CVSSv3Vector)
		}
		if patch.CVSSv4Vector == nil {
			t.Fatal("CVSSv4Vector is nil")
		}
		if *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N" {
			t.Errorf("CVSSv4Vector = %q, want CVSS:4.0/...", *patch.CVSSv4Vector)
		}
	})

	t.Run("first CVSS vector wins when duplicates present", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-cvss-dup-0001",
			Severity: []osvSeverity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.CVSSv3Vector == nil {
			t.Fatal("CVSSv3Vector is nil")
		}
		if *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Errorf("CVSSv3Vector = %q, want first vector", *patch.CVSSv3Vector)
		}
	})

	t.Run("references with type as tag", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-ref-test-0001",
			References: []osvReference{
				{Type: "WEB", URL: "https://example.com/advisory"},
				{Type: "PACKAGE", URL: "https://pkg.go.dev/vuln/GO-2024-0001"},
				{Type: "", URL: "https://example.com/no-type"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.References) != 3 {
			t.Fatalf("References len = %d, want 3", len(patch.References))
		}
		// First reference has a type tag.
		if len(patch.References[0].Tags) != 1 || patch.References[0].Tags[0] != "WEB" {
			t.Errorf("References[0].Tags = %v, want [WEB]", patch.References[0].Tags)
		}
		if patch.References[0].URL != "https://example.com/advisory" {
			t.Errorf("References[0].URL = %q, want %q", patch.References[0].URL, "https://example.com/advisory")
		}
		// Third reference has no type, so tags should be nil/empty.
		if len(patch.References[2].Tags) != 0 {
			t.Errorf("References[2].Tags = %v, want empty", patch.References[2].Tags)
		}
	})

	t.Run("empty URL references skipped", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-ref-empty-0001",
			References: []osvReference{
				{Type: "WEB", URL: ""},
				{Type: "PACKAGE", URL: "https://example.com"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(patch.References) != 1 {
			t.Fatalf("References len = %d, want 1 (empty URL should be skipped)", len(patch.References))
		}
	})

	t.Run("empty ID returns nil", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{ID: "", Summary: "No ID advisory."}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch != nil {
			t.Error("expected nil patch for empty ID")
		}
	})

	t.Run("null bytes stripped from fields", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID:      "GHSA-null\x00-test",
			Details: "Description with\x00null bytes.",
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.SourceID != "GHSA-null-test" {
			t.Errorf("SourceID = %q, want %q (null byte should be stripped)", patch.SourceID, "GHSA-null-test")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Description withnull bytes." {
			t.Errorf("DescriptionPrimary = %v, want null bytes stripped", patch.DescriptionPrimary)
		}
	})

	t.Run("not withdrawn when field absent", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{ID: "GHSA-active-0001"}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.IsWithdrawn {
			t.Error("IsWithdrawn = true, want false for active advisory")
		}
		if patch.Status != "" {
			t.Errorf("Status = %q, want empty for active advisory", patch.Status)
		}
	})

	t.Run("no description when both empty", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{ID: "GHSA-nodesc-0001", Details: "", Summary: ""}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.DescriptionPrimary != nil {
			t.Errorf("DescriptionPrimary = %v, want nil", patch.DescriptionPrimary)
		}
	})

	t.Run("affected packages skipped when ecosystem or name empty", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-pkg-skip-0001",
			Affected: []osvAffected{
				{
					Package: osvPackage{Ecosystem: "", Name: "foo"},
					Ranges:  []osvRange{{Type: "SEMVER", Events: json.RawMessage(`[{"introduced":"0"}]`)}},
				},
				{
					Package: osvPackage{Ecosystem: "Go", Name: ""},
					Ranges:  []osvRange{{Type: "SEMVER", Events: json.RawMessage(`[{"introduced":"0"}]`)}},
				},
				{
					Package: osvPackage{Ecosystem: "npm", Name: "bar"},
					Ranges:  []osvRange{{Type: "SEMVER", Events: json.RawMessage(`[{"introduced":"0"}]`)}},
				},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(patch.AffectedPackages) != 1 {
			t.Fatalf("AffectedPackages len = %d, want 1 (empty eco/name skipped)", len(patch.AffectedPackages))
		}
		if patch.AffectedPackages[0].Ecosystem != "npm" {
			t.Errorf("surviving package ecosystem = %q, want %q", patch.AffectedPackages[0].Ecosystem, "npm")
		}
	})

	t.Run("empty CVSS vector skipped", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-cvss-empty-0001",
			Severity: []osvSeverity{
				{Type: "CVSS_V3", Score: ""},
				{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.CVSSv3Vector != nil {
			t.Errorf("CVSSv3Vector = %v, want nil (empty score)", patch.CVSSv3Vector)
		}
		if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N" {
			t.Errorf("CVSSv4Vector = %v, want CVSS:4.0/...", patch.CVSSv4Vector)
		}
	})

	t.Run("case insensitive CVSS type matching", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-cvss-case-0001",
			Severity: []osvSeverity{
				{Type: "cvss_v3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.CVSSv3Vector == nil {
			t.Fatal("CVSSv3Vector is nil, expected lowercase type to match")
		}
		if *patch.CVSSv3Vector != "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N" {
			t.Errorf("CVSSv3Vector = %q", *patch.CVSSv3Vector)
		}
	})

	t.Run("multiple affected packages with multiple ranges", func(t *testing.T) {
		t.Parallel()
		adv := osvAdvisory{
			ID: "GHSA-multi-pkg-0001",
			Affected: []osvAffected{
				{
					Package: osvPackage{Ecosystem: "Go", Name: "golang.org/x/crypto"},
					Ranges: []osvRange{
						{Type: "SEMVER", Events: json.RawMessage(`[{"introduced":"0"},{"fixed":"0.17.0"}]`)},
						{Type: "SEMVER", Events: json.RawMessage(`[{"introduced":"0.18.0"},{"fixed":"0.19.1"}]`)},
					},
				},
			},
		}
		b, _ := json.Marshal(adv)
		patch, err := parseAdvisory(strings.NewReader(string(b)))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(patch.AffectedPackages) != 2 {
			t.Fatalf("AffectedPackages len = %d, want 2", len(patch.AffectedPackages))
		}
		if patch.AffectedPackages[0].Fixed != "0.17.0" {
			t.Errorf("first range fixed = %q, want %q", patch.AffectedPackages[0].Fixed, "0.17.0")
		}
		if patch.AffectedPackages[1].Introduced != "0.18.0" {
			t.Errorf("second range introduced = %q, want %q", patch.AffectedPackages[1].Introduced, "0.18.0")
		}
	})
}

func TestExtractPackageRange(t *testing.T) {
	t.Parallel()

	t.Run("introduced and fixed events", func(t *testing.T) {
		t.Parallel()
		rng := osvRange{
			Type:   "SEMVER",
			Events: json.RawMessage(`[{"introduced":"1.0.0"},{"fixed":"1.2.3"}]`),
		}
		pkg := extractPackageRange("npm", "lodash", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		if pkg.Ecosystem != "npm" {
			t.Errorf("Ecosystem = %q, want %q", pkg.Ecosystem, "npm")
		}
		if pkg.PackageName != "lodash" {
			t.Errorf("PackageName = %q, want %q", pkg.PackageName, "lodash")
		}
		if pkg.RangeType != "SEMVER" {
			t.Errorf("RangeType = %q, want %q", pkg.RangeType, "SEMVER")
		}
		if pkg.Introduced != "1.0.0" {
			t.Errorf("Introduced = %q, want %q", pkg.Introduced, "1.0.0")
		}
		if pkg.Fixed != "1.2.3" {
			t.Errorf("Fixed = %q, want %q", pkg.Fixed, "1.2.3")
		}
		if pkg.LastAffected != "" {
			t.Errorf("LastAffected = %q, want empty", pkg.LastAffected)
		}
	})

	t.Run("last_affected event", func(t *testing.T) {
		t.Parallel()
		rng := osvRange{
			Type:   "ECOSYSTEM",
			Events: json.RawMessage(`[{"introduced":"2.0.0"},{"last_affected":"2.5.9"}]`),
		}
		pkg := extractPackageRange("PyPI", "requests", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		if pkg.Introduced != "2.0.0" {
			t.Errorf("Introduced = %q, want %q", pkg.Introduced, "2.0.0")
		}
		if pkg.LastAffected != "2.5.9" {
			t.Errorf("LastAffected = %q, want %q", pkg.LastAffected, "2.5.9")
		}
		if pkg.Fixed != "" {
			t.Errorf("Fixed = %q, want empty", pkg.Fixed)
		}
	})

	t.Run("empty events returns package with zero-value strings", func(t *testing.T) {
		t.Parallel()
		rng := osvRange{
			Type:   "GIT",
			Events: nil,
		}
		pkg := extractPackageRange("Go", "stdlib", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		if pkg.Introduced != "" {
			t.Errorf("Introduced = %q, want empty", pkg.Introduced)
		}
		if pkg.Fixed != "" {
			t.Errorf("Fixed = %q, want empty", pkg.Fixed)
		}
		if pkg.LastAffected != "" {
			t.Errorf("LastAffected = %q, want empty", pkg.LastAffected)
		}
		if pkg.RangeType != "GIT" {
			t.Errorf("RangeType = %q, want %q", pkg.RangeType, "GIT")
		}
	})

	t.Run("raw events JSON preserved", func(t *testing.T) {
		t.Parallel()
		rawEvents := json.RawMessage(`[{"introduced":"0"},{"fixed":"1.0.0"}]`)
		rng := osvRange{
			Type:   "SEMVER",
			Events: rawEvents,
		}
		pkg := extractPackageRange("npm", "express", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		if string(pkg.Events) != string(rawEvents) {
			t.Errorf("Events = %s, want %s", string(pkg.Events), string(rawEvents))
		}
	})

	t.Run("malformed event objects skipped gracefully", func(t *testing.T) {
		t.Parallel()
		rng := osvRange{
			Type:   "SEMVER",
			Events: json.RawMessage(`[{"introduced":"1.0.0"},42,{"fixed":"2.0.0"}]`),
		}
		pkg := extractPackageRange("npm", "foo", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		if pkg.Introduced != "1.0.0" {
			t.Errorf("Introduced = %q, want %q", pkg.Introduced, "1.0.0")
		}
		if pkg.Fixed != "2.0.0" {
			t.Errorf("Fixed = %q, want %q", pkg.Fixed, "2.0.0")
		}
	})

	t.Run("malformed events array is handled", func(t *testing.T) {
		t.Parallel()
		rng := osvRange{
			Type:   "SEMVER",
			Events: json.RawMessage(`not-json`),
		}
		pkg := extractPackageRange("npm", "bar", rng)
		if pkg == nil {
			t.Fatal("expected non-nil package")
		}
		// With malformed JSON, no events are parsed — fields stay zero-value.
		if pkg.Introduced != "" {
			t.Errorf("Introduced = %q, want empty", pkg.Introduced)
		}
	})
}

// TestParseAdvisoryInvalidJSON verifies that malformed JSON returns an error.
func TestParseAdvisoryInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := parseAdvisory(strings.NewReader("{invalid json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestAdapterRateLimiterNonNil verifies that New always initialises the
// per-adapter rate limiter. A nil limiter would panic on Wait.
func TestAdapterRateLimiterNonNil(t *testing.T) {
	t.Parallel()

	a := New(nil)
	if a == nil {
		t.Fatal("New returned nil")
	}
	if a.rateLimiter == nil {
		t.Fatal("rateLimiter is nil — adapter would panic on Wait")
	}
	if a.client == nil {
		t.Fatal("client is nil — adapter would panic on Fetch")
	}
}

// TestNullByteStripping verifies the shared StripNullBytes utility works
// correctly from the OSV package's perspective.
func TestNullByteStripping(t *testing.T) {
	t.Parallel()

	dirty := "GHSA-1234\x00-5678"
	cleaned := feed.StripNullBytes(dirty)
	want := "GHSA-1234-5678"
	if cleaned != want {
		t.Errorf("StripNullBytes(%q) = %q, want %q", dirty, cleaned, want)
	}
}
