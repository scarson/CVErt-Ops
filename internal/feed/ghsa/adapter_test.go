// ABOUTME: Unit tests for GHSA feed adapter parse/convert functions and Fetch integration.
// ABOUTME: Covers parseLinkHeader, parseAdvisory, and Fetch with httptest.
package ghsa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseLinkHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "standard link header with rel next",
			header: `<https://api.github.com/advisories?after=Y3Vyc29yMQ&per_page=100>; rel="next"`,
			want:   "Y3Vyc29yMQ",
		},
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
		{
			name:   "no rel next",
			header: `<https://api.github.com/advisories?after=Y3Vyc29yMQ&per_page=100>; rel="prev"`,
			want:   "",
		},
		{
			name:   "multiple parts only next has cursor",
			header: `<https://api.github.com/advisories?after=abc123&per_page=100>; rel="prev", <https://api.github.com/advisories?after=def456&per_page=100>; rel="next"`,
			want:   "def456",
		},
		{
			name:   "malformed URL in link",
			header: `<://not-a-url>; rel="next"`,
			want:   "",
		},
		{
			name:   "no semicolon separator",
			header: `<https://api.github.com/advisories?after=abc>`,
			want:   "",
		},
		{
			name:   "rel next without after param",
			header: `<https://api.github.com/advisories?per_page=100>; rel="next"`,
			want:   "",
		},
		{
			name:   "case insensitive rel",
			header: `<https://api.github.com/advisories?after=caseCursor&per_page=100>; REL="next"`,
			want:   "caseCursor",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseLinkHeader(tc.header)
			if got != tc.want {
				t.Errorf("parseLinkHeader(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestParseAdvisory(t *testing.T) {
	t.Parallel()

	strPtr := func(s string) *string { return &s }
	floatPtr := func(f float64) *float64 { return &f }

	t.Run("normal advisory with cve_id", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-xxxx-yyyy-zzzz",
			CVEID:       strPtr("CVE-2024-12345"),
			Summary:     "Short summary",
			Description: strPtr("A longer description of the vulnerability."),
			PublishedAt: "2024-01-15T10:00:00Z",
			UpdatedAt:   "2024-01-16T12:00:00Z",
			Severity:    "high",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "CVE-2024-12345" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-12345")
		}
		if patch.SourceID != "GHSA-xxxx-yyyy-zzzz" {
			t.Errorf("SourceID = %q, want %q", patch.SourceID, "GHSA-xxxx-yyyy-zzzz")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "A longer description of the vulnerability." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "A longer description of the vulnerability.")
		}
		if patch.DatePublished == nil {
			t.Error("DatePublished is nil, expected non-nil")
		}
		if patch.DateModified == nil {
			t.Error("DateModified is nil, expected non-nil")
		}
	})

	t.Run("null cve_id uses ghsa_id", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:  "GHSA-aaaa-bbbb-cccc",
			CVEID:   nil,
			Summary: "No CVE assigned",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "GHSA-aaaa-bbbb-cccc" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "GHSA-aaaa-bbbb-cccc")
		}
		if patch.SourceID != "GHSA-aaaa-bbbb-cccc" {
			t.Errorf("SourceID = %q, want %q", patch.SourceID, "GHSA-aaaa-bbbb-cccc")
		}
	})

	t.Run("CVE from identifiers array used when cve_id is nil", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-dddd-eeee-ffff",
			CVEID:  nil,
			Identifiers: []ghsaIdentifier{
				{Type: "GHSA", Value: "GHSA-dddd-eeee-ffff"},
				{Type: "CVE", Value: "CVE-2024-99999"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVEID != "CVE-2024-99999" {
			t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-99999")
		}
		if patch.SourceID != "GHSA-dddd-eeee-ffff" {
			t.Errorf("SourceID = %q, want %q", patch.SourceID, "GHSA-dddd-eeee-ffff")
		}
	})

	t.Run("top-level cve_id takes precedence over identifiers", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-1111-2222-3333",
			CVEID:  strPtr("CVE-2024-11111"),
			Identifiers: []ghsaIdentifier{
				{Type: "CVE", Value: "CVE-2024-22222"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		// ResolveCanonicalID picks the first CVE match from aliases.
		// top-level cve_id is appended first, so it wins.
		if patch.CVEID != "CVE-2024-11111" {
			t.Errorf("CVEID = %q, want %q (top-level cve_id should win)", patch.CVEID, "CVE-2024-11111")
		}
	})

	t.Run("withdrawn advisory", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-with-draw-0001",
			WithdrawnAt: strPtr("2024-02-01T00:00:00Z"),
		}
		patch := parseAdvisory(rec)
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

	t.Run("not withdrawn when withdrawn_at nil", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-active-0001",
			WithdrawnAt: nil,
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.IsWithdrawn {
			t.Error("IsWithdrawn = true, want false")
		}
	})

	t.Run("not withdrawn when withdrawn_at empty string", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-active-0002",
			WithdrawnAt: strPtr(""),
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.IsWithdrawn {
			t.Error("IsWithdrawn = true, want false for empty withdrawn_at")
		}
	})

	t.Run("description preferred over summary", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-desc-test-0001",
			Description: strPtr("Long description here."),
			Summary:     "Short summary.",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Long description here." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "Long description here.")
		}
	})

	t.Run("summary used when description nil", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-desc-test-0002",
			Description: nil,
			Summary:     "Fallback summary.",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Fallback summary." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "Fallback summary.")
		}
	})

	t.Run("summary used when description empty string", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-desc-test-0003",
			Description: strPtr(""),
			Summary:     "Fallback summary.",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "Fallback summary." {
			t.Errorf("DescriptionPrimary = %v, want %q", patch.DescriptionPrimary, "Fallback summary.")
		}
	})

	t.Run("cvss_severities v3 and v4 preferred over top-level cvss", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cvss-sev-0001",
			CVSS: &ghsaCVSSEntry{
				Score:        5.0,
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			},
			CVSSSeverities: &ghsaCVSSSeverities{
				CVSSv3: &ghsaCVSSEntry{
					Score:        9.8,
					VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				},
				CVSSv4: &ghsaCVSSEntry{
					Score:        8.5,
					VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",
				},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		// cvss_severities.cvss_v3 should be used, not top-level cvss.
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 9.8 {
			t.Errorf("CVSSv3Score = %v, want 9.8", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Errorf("CVSSv3Vector = %v, want CVSS:3.1/...", patch.CVSSv3Vector)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 8.5 {
			t.Errorf("CVSSv4Score = %v, want 8.5", patch.CVSSv4Score)
		}
		if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N" {
			t.Errorf("CVSSv4Vector = %v, want CVSS:4.0/...", patch.CVSSv4Vector)
		}
	})

	t.Run("fallback to top-level cvss when cvss_severities missing", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cvss-fb-0001",
			CVSS: &ghsaCVSSEntry{
				Score:        7.5,
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
			CVSSSeverities: nil,
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Errorf("CVSSv3Score = %v, want 7.5 (fallback to top-level)", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
			t.Errorf("CVSSv3Vector = %v, want CVSS:3.1/...", patch.CVSSv3Vector)
		}
	})

	t.Run("top-level cvss used when cvss_severities has no v3", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cvss-fb-0002",
			CVSS: &ghsaCVSSEntry{
				Score:        6.0,
				VectorString: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N",
			},
			CVSSSeverities: &ghsaCVSSSeverities{
				CVSSv3: nil, // v3 not set in severities
				CVSSv4: &ghsaCVSSEntry{Score: 3.0, VectorString: "CVSS:4.0/AV:L"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		// cvss_severities.cvss_v3 is nil, so fallback to top-level cvss for v3.
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 6.0 {
			t.Errorf("CVSSv3Score = %v, want 6.0 (fallback)", patch.CVSSv3Score)
		}
		// CVSSv4 from severities.
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 3.0 {
			t.Errorf("CVSSv4Score = %v, want 3.0", patch.CVSSv4Score)
		}
	})

	t.Run("zero score in cvss_severities accepted", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cvss-zero-0001",
			CVSS: &ghsaCVSSEntry{
				Score:        4.5,
				VectorString: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
			},
			CVSSSeverities: &ghsaCVSSSeverities{
				CVSSv3: &ghsaCVSSEntry{Score: 0, VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		// Zero score in cvss_severities is valid — should be used, not skipped.
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 0.0 {
			t.Errorf("CVSSv3Score = %v, want 0.0 (zero score is valid)", patch.CVSSv3Score)
		}
	})

	t.Run("CWE IDs extracted", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cwe-test-0001",
			CWEs: []ghsaCWE{
				{CWEID: "CWE-79", Name: "Cross-site Scripting"},
				{CWEID: "CWE-89", Name: "SQL Injection"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.CWEIDs) != 2 {
			t.Fatalf("CWEIDs len = %d, want 2", len(patch.CWEIDs))
		}
		if patch.CWEIDs[0] != "CWE-79" {
			t.Errorf("CWEIDs[0] = %q, want %q", patch.CWEIDs[0], "CWE-79")
		}
		if patch.CWEIDs[1] != "CWE-89" {
			t.Errorf("CWEIDs[1] = %q, want %q", patch.CWEIDs[1], "CWE-89")
		}
	})

	t.Run("empty CWE IDs skipped", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cwe-empty-0001",
			CWEs: []ghsaCWE{
				{CWEID: "", Name: "Empty"},
				{CWEID: "CWE-200", Name: "Info Exposure"},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.CWEIDs) != 1 {
			t.Fatalf("CWEIDs len = %d, want 1 (empty skipped)", len(patch.CWEIDs))
		}
		if patch.CWEIDs[0] != "CWE-200" {
			t.Errorf("CWEIDs[0] = %q, want %q", patch.CWEIDs[0], "CWE-200")
		}
	})

	t.Run("affected packages with first_patched_version", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-pkg-test-0001",
			Vulnerabilities: []ghsaVulnerability{
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "npm", Name: "lodash"},
					FirstPatchedVersion: strPtr("4.17.21"),
				},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.AffectedPackages) != 1 {
			t.Fatalf("AffectedPackages len = %d, want 1", len(patch.AffectedPackages))
		}
		pkg := patch.AffectedPackages[0]
		if pkg.Ecosystem != "npm" {
			t.Errorf("Ecosystem = %q, want %q", pkg.Ecosystem, "npm")
		}
		if pkg.PackageName != "lodash" {
			t.Errorf("PackageName = %q, want %q", pkg.PackageName, "lodash")
		}
		if pkg.RangeType != "ECOSYSTEM" {
			t.Errorf("RangeType = %q, want %q", pkg.RangeType, "ECOSYSTEM")
		}
		if pkg.Introduced != "0" {
			t.Errorf("Introduced = %q, want %q", pkg.Introduced, "0")
		}
		if pkg.Fixed != "4.17.21" {
			t.Errorf("Fixed = %q, want %q", pkg.Fixed, "4.17.21")
		}
		// Synthetic events JSON should contain introduced and fixed.
		if pkg.Events == nil {
			t.Fatal("Events is nil, expected synthetic events JSON")
		}
		var events []map[string]string
		if err := json.Unmarshal(pkg.Events, &events); err != nil {
			t.Fatalf("unmarshal events: %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("events len = %d, want 2", len(events))
		}
		if events[0]["introduced"] != "0" {
			t.Errorf("events[0].introduced = %q, want %q", events[0]["introduced"], "0")
		}
		if events[1]["fixed"] != "4.17.21" {
			t.Errorf("events[1].fixed = %q, want %q", events[1]["fixed"], "4.17.21")
		}
	})

	t.Run("affected package without first_patched_version has no events", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-pkg-nopatch-0001",
			Vulnerabilities: []ghsaVulnerability{
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "PyPI", Name: "requests"},
					FirstPatchedVersion: nil,
				},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.AffectedPackages) != 1 {
			t.Fatalf("AffectedPackages len = %d, want 1", len(patch.AffectedPackages))
		}
		pkg := patch.AffectedPackages[0]
		if pkg.Fixed != "" {
			t.Errorf("Fixed = %q, want empty", pkg.Fixed)
		}
		if pkg.Events != nil {
			t.Errorf("Events = %s, want nil (no patched version)", string(pkg.Events))
		}
	})

	t.Run("affected packages skipped when ecosystem or name empty", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-pkg-skip-0001",
			Vulnerabilities: []ghsaVulnerability{
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "", Name: "foo"},
				},
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "npm", Name: ""},
				},
				{
					Package: struct {
						Ecosystem string `json:"ecosystem"`
						Name      string `json:"name"`
					}{Ecosystem: "Go", Name: "bar"},
				},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.AffectedPackages) != 1 {
			t.Fatalf("AffectedPackages len = %d, want 1 (empty eco/name skipped)", len(patch.AffectedPackages))
		}
		if patch.AffectedPackages[0].PackageName != "bar" {
			t.Errorf("surviving package name = %q, want %q", patch.AffectedPackages[0].PackageName, "bar")
		}
	})

	t.Run("references include html_url first then references array", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:  "GHSA-ref-test-0001",
			HTMLURL: "https://github.com/advisories/GHSA-ref-test-0001",
			References: []string{
				"https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
				"https://example.com/patch",
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.References) != 3 {
			t.Fatalf("References len = %d, want 3", len(patch.References))
		}
		// First reference is the html_url with ADVISORY tag.
		if patch.References[0].URL != "https://github.com/advisories/GHSA-ref-test-0001" {
			t.Errorf("References[0].URL = %q, want html_url", patch.References[0].URL)
		}
		if len(patch.References[0].Tags) != 1 || patch.References[0].Tags[0] != "ADVISORY" {
			t.Errorf("References[0].Tags = %v, want [ADVISORY]", patch.References[0].Tags)
		}
		// Subsequent references from the references array have no tags.
		if patch.References[1].URL != "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" {
			t.Errorf("References[1].URL = %q", patch.References[1].URL)
		}
		if len(patch.References[1].Tags) != 0 {
			t.Errorf("References[1].Tags = %v, want empty", patch.References[1].Tags)
		}
	})

	t.Run("empty html_url not added to references", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:  "GHSA-ref-nohtml-0001",
			HTMLURL: "",
			References: []string{
				"https://example.com",
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.References) != 1 {
			t.Fatalf("References len = %d, want 1", len(patch.References))
		}
		if patch.References[0].URL != "https://example.com" {
			t.Errorf("References[0].URL = %q", patch.References[0].URL)
		}
	})

	t.Run("empty reference URLs skipped", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-ref-empty-0001",
			References: []string{
				"",
				"https://example.com",
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(patch.References) != 1 {
			t.Fatalf("References len = %d, want 1", len(patch.References))
		}
	})

	t.Run("empty ghsa_id returns nil", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{GHSAID: "", Summary: "No ID advisory."}
		patch := parseAdvisory(rec)
		if patch != nil {
			t.Error("expected nil patch for empty GHSA ID")
		}
	})

	t.Run("severity unknown dropped", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:   "GHSA-sev-unk-0001",
			Severity: "unknown",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.Severity != nil {
			t.Errorf("Severity = %v, want nil (unknown should be dropped)", patch.Severity)
		}
	})

	t.Run("severity uppercased", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			input string
			want  string
		}{
			{"critical", "CRITICAL"},
			{"high", "HIGH"},
			{"medium", "MEDIUM"},
			{"low", "LOW"},
		}
		for _, tc := range tests {
			rec := ghsaAdvisory{
				GHSAID:   "GHSA-sev-test-0001",
				Severity: tc.input,
			}
			patch := parseAdvisory(rec)
			if patch == nil {
				t.Fatalf("expected non-nil patch for severity %q", tc.input)
			}
			if patch.Severity == nil {
				t.Fatalf("Severity is nil for input %q", tc.input)
			}
			if *patch.Severity != tc.want {
				t.Errorf("Severity for input %q = %q, want %q", tc.input, *patch.Severity, tc.want)
			}
		}
	})

	t.Run("no description when both nil/empty", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:      "GHSA-nodesc-0001",
			Description: nil,
			Summary:     "",
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.DescriptionPrimary != nil {
			t.Errorf("DescriptionPrimary = %v, want nil", patch.DescriptionPrimary)
		}
	})

	t.Run("no CVSS when all sources nil", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID:         "GHSA-nocvss-0001",
			CVSS:           nil,
			CVSSSeverities: nil,
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		if patch.CVSSv3Score != nil {
			t.Errorf("CVSSv3Score = %v, want nil", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector != nil {
			t.Errorf("CVSSv3Vector = %v, want nil", patch.CVSSv3Vector)
		}
		if patch.CVSSv4Score != nil {
			t.Errorf("CVSSv4Score = %v, want nil", patch.CVSSv4Score)
		}
		if patch.CVSSv4Vector != nil {
			t.Errorf("CVSSv4Vector = %v, want nil", patch.CVSSv4Vector)
		}
	})

	// Suppress the "declared and not used" error for floatPtr.
	_ = floatPtr
}

func TestParseAdvisory_NullByteStripping(t *testing.T) {
	t.Parallel()

	strPtr := func(s string) *string { return &s }

	rec := ghsaAdvisory{
		GHSAID:      "GHSA-null\x00-test-0001",
		CVEID:       strPtr("CVE-2024\x00-55555"),
		Summary:     "Summary\x00 with null.",
		Description: strPtr("Description\x00 with null bytes."),
		Severity:    "hi\x00gh",
		PublishedAt: "2024-01-15T10:00:00Z",
		UpdatedAt:   "2024-01-16T12:00:00Z",
		CVSS: &ghsaCVSSEntry{
			Score:        7.5,
			VectorString: "CVSS:3.1/AV:\x00N/AC:L",
		},
		CVSSSeverities: &ghsaCVSSSeverities{
			CVSSv3: &ghsaCVSSEntry{
				Score:        9.8,
				VectorString: "CVSS:3.1/AV:N\x00/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
			CVSSv4: &ghsaCVSSEntry{
				Score:        8.5,
				VectorString: "CVSS:4.0/AV:N\x00/AC:L/AT:N/PR:N/UI:N",
			},
		},
		CWEs: []ghsaCWE{
			{CWEID: "CWE-\x0079", Name: "XSS"},
		},
		Vulnerabilities: []ghsaVulnerability{
			{
				Package: struct {
					Ecosystem string `json:"ecosystem"`
					Name      string `json:"name"`
				}{Ecosystem: "n\x00pm", Name: "lod\x00ash"},
				FirstPatchedVersion: strPtr("4.17\x00.21"),
			},
		},
		Identifiers: []ghsaIdentifier{
			{Type: "CVE", Value: "CVE-2024\x00-55555"},
		},
		HTMLURL: "https://github\x00.com/advisories/GHSA-null-test-0001",
		References: []string{
			"https://example\x00.com/ref",
		},
	}

	patch := parseAdvisory(rec)
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}

	// GHSA ID (SourceID) should be stripped.
	if strings.Contains(patch.SourceID, "\x00") {
		t.Errorf("SourceID contains null byte: %q", patch.SourceID)
	}
	if patch.SourceID != "GHSA-null-test-0001" {
		t.Errorf("SourceID = %q, want %q", patch.SourceID, "GHSA-null-test-0001")
	}

	// CVE ID from top-level cve_id should be stripped.
	if strings.Contains(patch.CVEID, "\x00") {
		t.Errorf("CVEID contains null byte: %q", patch.CVEID)
	}
	if patch.CVEID != "CVE-2024-55555" {
		t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-55555")
	}

	// Description should be stripped (prefers description over summary).
	if patch.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary is nil")
	}
	if strings.Contains(*patch.DescriptionPrimary, "\x00") {
		t.Errorf("DescriptionPrimary contains null byte: %q", *patch.DescriptionPrimary)
	}
	if *patch.DescriptionPrimary != "Description with null bytes." {
		t.Errorf("DescriptionPrimary = %q, want %q", *patch.DescriptionPrimary, "Description with null bytes.")
	}

	// Severity should be stripped.
	if patch.Severity == nil {
		t.Fatal("Severity is nil")
	}
	if strings.Contains(*patch.Severity, "\x00") {
		t.Errorf("Severity contains null byte: %q", *patch.Severity)
	}
	if *patch.Severity != "HIGH" {
		t.Errorf("Severity = %q, want %q", *patch.Severity, "HIGH")
	}

	// CVSS v3 vector from cvss_severities should be stripped.
	if patch.CVSSv3Vector == nil {
		t.Fatal("CVSSv3Vector is nil")
	}
	if strings.Contains(*patch.CVSSv3Vector, "\x00") {
		t.Errorf("CVSSv3Vector contains null byte: %q", *patch.CVSSv3Vector)
	}
	if *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3Vector = %q, want %q", *patch.CVSSv3Vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	}

	// CVSS v4 vector from cvss_severities should be stripped.
	if patch.CVSSv4Vector == nil {
		t.Fatal("CVSSv4Vector is nil")
	}
	if strings.Contains(*patch.CVSSv4Vector, "\x00") {
		t.Errorf("CVSSv4Vector contains null byte: %q", *patch.CVSSv4Vector)
	}
	if *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N" {
		t.Errorf("CVSSv4Vector = %q, want %q", *patch.CVSSv4Vector, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N")
	}

	// CWE IDs should be stripped.
	if len(patch.CWEIDs) != 1 {
		t.Fatalf("CWEIDs len = %d, want 1", len(patch.CWEIDs))
	}
	if strings.Contains(patch.CWEIDs[0], "\x00") {
		t.Errorf("CWEIDs[0] contains null byte: %q", patch.CWEIDs[0])
	}
	if patch.CWEIDs[0] != "CWE-79" {
		t.Errorf("CWEIDs[0] = %q, want %q", patch.CWEIDs[0], "CWE-79")
	}

	// Affected packages: ecosystem, name, fixed version should be stripped.
	if len(patch.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages len = %d, want 1", len(patch.AffectedPackages))
	}
	pkg := patch.AffectedPackages[0]
	if strings.Contains(pkg.Ecosystem, "\x00") {
		t.Errorf("Ecosystem contains null byte: %q", pkg.Ecosystem)
	}
	if pkg.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want %q", pkg.Ecosystem, "npm")
	}
	if strings.Contains(pkg.PackageName, "\x00") {
		t.Errorf("PackageName contains null byte: %q", pkg.PackageName)
	}
	if pkg.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want %q", pkg.PackageName, "lodash")
	}
	if strings.Contains(pkg.Fixed, "\x00") {
		t.Errorf("Fixed contains null byte: %q", pkg.Fixed)
	}
	if pkg.Fixed != "4.17.21" {
		t.Errorf("Fixed = %q, want %q", pkg.Fixed, "4.17.21")
	}

	// HTML URL reference should be stripped.
	if len(patch.References) < 1 {
		t.Fatalf("References len = %d, want at least 1", len(patch.References))
	}
	if strings.Contains(patch.References[0].URL, "\x00") {
		t.Errorf("References[0].URL (html_url) contains null byte: %q", patch.References[0].URL)
	}
	if patch.References[0].URL != "https://github.com/advisories/GHSA-null-test-0001" {
		t.Errorf("References[0].URL = %q, want %q", patch.References[0].URL, "https://github.com/advisories/GHSA-null-test-0001")
	}

	// Additional reference URLs should be stripped.
	if len(patch.References) < 2 {
		t.Fatalf("References len = %d, want at least 2", len(patch.References))
	}
	if strings.Contains(patch.References[1].URL, "\x00") {
		t.Errorf("References[1].URL contains null byte: %q", patch.References[1].URL)
	}
	if patch.References[1].URL != "https://example.com/ref" {
		t.Errorf("References[1].URL = %q, want %q", patch.References[1].URL, "https://example.com/ref")
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

// --- Fetch-level integration tests (httptest + redirectTransport) ---

// redirectTransport intercepts outbound requests and rewrites their scheme/host
// to point at the httptest server. This lets us test Fetch end-to-end without
// modifying the hardcoded advisoriesURL const.
type redirectTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return rt.inner.RoundTrip(req)
}

// validGHSAAdvisory is a minimal GHSA REST API advisory for Fetch tests.
// The REST response is a top-level JSON array of these objects.
const validGHSAAdvisory = `[
	{
		"ghsa_id": "GHSA-test-0001-aaaa",
		"cve_id": "CVE-2025-10001",
		"summary": "Test advisory for Fetch",
		"description": "A test advisory used by Fetch-level tests.",
		"severity": "high",
		"published_at": "2025-01-10T10:00:00Z",
		"updated_at": "2025-01-11T12:00:00Z",
		"withdrawn_at": null,
		"cvss": null,
		"cvss_severities": null,
		"cwes": [],
		"vulnerabilities": [],
		"references": [],
		"identifiers": [
			{"type": "GHSA", "value": "GHSA-test-0001-aaaa"},
			{"type": "CVE", "value": "CVE-2025-10001"}
		],
		"html_url": "https://github.com/advisories/GHSA-test-0001-aaaa"
	}
]`

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validGHSAAdvisory))
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Patches) != 1 {
		t.Fatalf("len(Patches) = %d, want 1", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-10001" {
		t.Errorf("Patches[0].CVEID = %q, want CVE-2025-10001", result.Patches[0].CVEID)
	}
	if result.SourceMeta.SourceName != "ghsa" {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, "ghsa")
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor should be non-nil")
	}
	var cursor Cursor
	if err := json.Unmarshal(result.NextCursor, &cursor); err != nil {
		t.Fatalf("failed to unmarshal NextCursor: %v", err)
	}
	if cursor.Since == "" {
		t.Error("cursor.Since should be non-empty")
	}
	// The since timestamp should be parseable as RFC3339.
	if _, err := time.Parse(time.RFC3339, cursor.Since); err != nil {
		t.Errorf("cursor.Since %q is not valid RFC3339: %v", cursor.Since, err)
	}

	if !result.LastPage {
		t.Error("LastPage should be true — single page response has no Link next header")
	}
	for i, p := range result.Patches {
		if p.RawPayload == nil {
			t.Errorf("Patches[%d].RawPayload is nil", i)
		} else if !json.Valid(p.RawPayload) {
			t.Errorf("Patches[%d].RawPayload is not valid JSON", i)
		} else if !bytes.Contains(p.RawPayload, []byte(p.CVEID)) {
			t.Errorf("Patches[%d].RawPayload does not contain CVE ID %q", i, p.CVEID)
		}
	}
}

func TestFetch_OnePagePerCall(t *testing.T) {
	t.Parallel()

	page1 := `[{
		"ghsa_id": "GHSA-page-0001-aaaa",
		"cve_id": "CVE-2025-20001",
		"summary": "Page 1 advisory",
		"severity": "medium",
		"published_at": "2025-02-01T10:00:00Z",
		"updated_at": "2025-02-02T12:00:00Z",
		"cwes": [],
		"vulnerabilities": [],
		"references": [],
		"identifiers": [],
		"html_url": ""
	}]`

	page2 := `[{
		"ghsa_id": "GHSA-page-0002-bbbb",
		"cve_id": "CVE-2025-20002",
		"summary": "Page 2 advisory",
		"severity": "low",
		"published_at": "2025-02-03T10:00:00Z",
		"updated_at": "2025-02-04T12:00:00Z",
		"cwes": [],
		"vulnerabilities": [],
		"references": [],
		"identifiers": [],
		"html_url": ""
	}]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		switch afterParam := r.URL.Query().Get("after"); afterParam {
		case "":
			// First page: include Link header pointing to page 2.
			linkURL := fmt.Sprintf("<%s/advisories?after=cursor2&per_page=100>; rel=\"next\"", "https://api.github.com")
			w.Header().Set("Link", linkURL)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(page1))
		case "cursor2":
			// Second page: no Link header (last page).
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(page2))
		default:
			t.Errorf("unexpected after param: %q", afterParam)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	// First call: should return only page 1 with LastPage=false.
	result1, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch page 1: %v", err)
	}
	if len(result1.Patches) != 1 {
		t.Fatalf("page 1: len(Patches) = %d, want 1", len(result1.Patches))
	}
	if result1.Patches[0].CVEID != "CVE-2025-20001" {
		t.Errorf("page 1: CVEID = %q, want CVE-2025-20001", result1.Patches[0].CVEID)
	}
	if result1.LastPage {
		t.Error("page 1: LastPage should be false (more pages remain)")
	}

	// Verify cursor contains After for next page.
	var cur1 Cursor
	if err := json.Unmarshal(result1.NextCursor, &cur1); err != nil {
		t.Fatalf("unmarshal cursor 1: %v", err)
	}
	if cur1.After != "cursor2" {
		t.Errorf("cursor.After = %q, want %q", cur1.After, "cursor2")
	}

	// Second call with returned cursor: should return page 2 with LastPage=true.
	result2, err := adapter.Fetch(context.Background(), result1.NextCursor)
	if err != nil {
		t.Fatalf("Fetch page 2: %v", err)
	}
	if len(result2.Patches) != 1 {
		t.Fatalf("page 2: len(Patches) = %d, want 1", len(result2.Patches))
	}
	if result2.Patches[0].CVEID != "CVE-2025-20002" {
		t.Errorf("page 2: CVEID = %q, want CVE-2025-20002", result2.Patches[0].CVEID)
	}
	if !result2.LastPage {
		t.Error("page 2: LastPage should be true (no more pages)")
	}

	// Verify cursor has updated Since and no After.
	var cur2 Cursor
	if err := json.Unmarshal(result2.NextCursor, &cur2); err != nil {
		t.Fatalf("unmarshal cursor 2: %v", err)
	}
	if cur2.After != "" {
		t.Errorf("final cursor.After = %q, want empty", cur2.After)
	}
	if cur2.Since == "" {
		t.Error("final cursor.Since should be non-empty")
	}
}

func TestFetch_WithCursor(t *testing.T) {
	t.Parallel()

	sinceTimestamp := "2025-03-01T10:00:00Z"
	sinceTime, _ := time.Parse(time.RFC3339, sinceTimestamp)
	expectedUpdated := sinceTime.Add(-15 * time.Minute).UTC().Format(time.RFC3339)

	var receivedUpdated string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedUpdated = r.URL.Query().Get("updated")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	cursorJSON, _ := json.Marshal(Cursor{Since: sinceTimestamp})
	_, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The adapter should send `updated=>=TIMESTAMP` with the 15-minute overlap applied.
	wantUpdated := ">=" + expectedUpdated
	if receivedUpdated != wantUpdated {
		t.Errorf("updated param = %q, want %q (15-min overlap applied)", receivedUpdated, wantUpdated)
	}
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 403") {
		t.Errorf("error = %q, want it to contain 'HTTP 403'", err.Error())
	}
}

func TestFetch_TokenAuthHeaderSet(t *testing.T) {
	t.Parallel()

	var capturedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	// Construct adapter directly to inject a test token.
	adapter := &Adapter{ //nolint:gosec // G101 false positive: test-only token, not a real credential
		client:      client,
		rateLimiter: New(nil).rateLimiter,
		token:       "test-github-token-12345",
	}

	_, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantAuth := "Bearer test-github-token-12345"
	if capturedAuth != wantAuth {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, wantAuth)
	}
}

func TestFetch_NoTokenOmitsAuthHeader(t *testing.T) {
	t.Parallel()

	var capturedAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	// Construct adapter with empty token.
	adapter := &Adapter{
		client:      client,
		rateLimiter: New(nil).rateLimiter,
		token:       "",
	}

	_, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedAuth != "" {
		t.Errorf("Authorization header = %q, want empty (no token configured)", capturedAuth)
	}
}

func TestFetchPage_TypeErrorSkipsRecord(t *testing.T) {
	// Not parallel: captures global slog.Default.

	// A type error (wrong JSON type for a field) is recoverable — the decoder
	// consumed the token, so we can continue to the next record.
	body := `[
		{"ghsa_id": "GHSA-good-0001-aaaa", "cve_id": "CVE-2025-30001", "summary": "ok", "severity": "low", "published_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z", "cwes": [], "vulnerabilities": [], "references": [], "identifiers": [], "html_url": ""},
		"this is not a valid JSON object for a ghsaAdvisory",
		{"ghsa_id": "GHSA-good-0003-cccc", "cve_id": "CVE-2025-30003", "summary": "ok", "severity": "low", "published_at": "2025-01-03T00:00:00Z", "updated_at": "2025-01-04T00:00:00Z", "cwes": [], "vulnerabilities": [], "references": [], "identifiers": [], "html_url": ""}
	]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected no error (type errors are skippable), got: %v", err)
	}
	if len(result.Patches) != 2 {
		t.Fatalf("got %d patches, want 2 (malformed record should be skipped)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-30001" || result.Patches[1].CVEID != "CVE-2025-30003" {
		t.Errorf("wrong patches: %v, %v", result.Patches[0].CVEID, result.Patches[1].CVEID)
	}
	if !strings.Contains(buf.String(), "skipping malformed record") {
		t.Errorf("expected warning log about skipped record, got: %s", buf.String())
	}
}

func TestFetchPage_SyntaxErrorStopsStream(t *testing.T) {
	// Not parallel: captures global slog.Default.

	// A JSON syntax error corrupts the stream — remaining tokens are unreliable.
	// The parser should return records parsed so far and stop.
	body := `[
		{"ghsa_id": "GHSA-good-0001-aaaa", "cve_id": "CVE-2025-40001", "summary": "ok", "severity": "low", "published_at": "2025-01-01T00:00:00Z", "updated_at": "2025-01-02T00:00:00Z", "cwes": [], "vulnerabilities": [], "references": [], "identifiers": [], "html_url": ""},
		{INVALID_JSON},
		{"ghsa_id": "GHSA-good-0003-cccc", "cve_id": "CVE-2025-40003", "summary": "ok"}
	]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()

	var buf bytes.Buffer
	origHandler := slog.Default().Handler()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected no error (syntax error returns partial), got: %v", err)
	}
	if len(result.Patches) != 1 {
		t.Fatalf("got %d patches, want 1 (only first record before syntax error)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-40001" {
		t.Errorf("patch CVEID = %q, want CVE-2025-40001", result.Patches[0].CVEID)
	}
	if !strings.Contains(buf.String(), "syntax error") {
		t.Errorf("expected warning log about syntax error, got: %s", buf.String())
	}
}

func TestFetch_EmptyPage(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	target, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: target,
			inner:  http.DefaultTransport,
		},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Patches) != 0 {
		t.Fatalf("len(Patches) = %d, want 0", len(result.Patches))
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor should be non-nil even for empty results")
	}
}
