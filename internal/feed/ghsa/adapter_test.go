// ABOUTME: Unit tests for GHSA feed adapter pure parse/convert functions.
// ABOUTME: Covers parseLinkHeader and parseAdvisory.
package ghsa

import (
	"encoding/json"
	"testing"
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

	t.Run("zero score in cvss_severities ignored", func(t *testing.T) {
		t.Parallel()
		rec := ghsaAdvisory{
			GHSAID: "GHSA-cvss-zero-0001",
			CVSS: &ghsaCVSSEntry{
				Score:        4.5,
				VectorString: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N",
			},
			CVSSSeverities: &ghsaCVSSSeverities{
				CVSSv3: &ghsaCVSSEntry{Score: 0, VectorString: ""},
			},
		}
		patch := parseAdvisory(rec)
		if patch == nil {
			t.Fatal("expected non-nil patch")
		}
		// Zero-score v3 in severities should be skipped; fallback to top-level.
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 4.5 {
			t.Errorf("CVSSv3Score = %v, want 4.5 (zero-score severities skipped)", patch.CVSSv3Score)
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
			References: []ghsaReference{
				{URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"},
				{URL: "https://example.com/patch"},
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
			References: []ghsaReference{
				{URL: "https://example.com"},
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
			References: []ghsaReference{
				{URL: ""},
				{URL: "https://example.com"},
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
