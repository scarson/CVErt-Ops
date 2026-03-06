// ABOUTME: Regression test for GHSA adapter CVSS 0.0 rejection bug.
// ABOUTME: Validates that a CVSS base score of 0.0 is accepted, not silently dropped.
package ghsa

import (
	"testing"
)

func TestParseAdvisory_CVSSv3ZeroScore(t *testing.T) {
	t.Parallel()

	cveID := "CVE-2024-00000"
	rec := ghsaAdvisory{
		GHSAID:      "GHSA-test-0000-0000",
		CVEID:       &cveID,
		Severity:    "NONE",
		Summary:     "No impact",
		PublishedAt: "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		CVSSSeverities: &ghsaCVSSSeverities{
			CVSSv3: &ghsaCVSSEntry{
				Score:        0.0,
				VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			},
		},
	}

	patch := parseAdvisory(rec)
	if patch == nil {
		t.Fatal("parseAdvisory returned nil")
	}
	if patch.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score is nil; 0.0 score was rejected")
	}
	if *patch.CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %v, want 0.0", *patch.CVSSv3Score)
	}
}

func TestParseAdvisory_CVSSv4ZeroScore(t *testing.T) {
	t.Parallel()

	cveID := "CVE-2024-00001"
	rec := ghsaAdvisory{
		GHSAID:      "GHSA-test-0000-0001",
		CVEID:       &cveID,
		Severity:    "NONE",
		Summary:     "No impact V4",
		PublishedAt: "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		CVSSSeverities: &ghsaCVSSSeverities{
			CVSSv4: &ghsaCVSSEntry{
				Score:        0.0,
				VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
			},
		},
	}

	patch := parseAdvisory(rec)
	if patch == nil {
		t.Fatal("parseAdvisory returned nil")
	}
	if patch.CVSSv4Score == nil {
		t.Fatal("CVSSv4Score is nil; 0.0 score was rejected")
	}
	if *patch.CVSSv4Score != 0.0 {
		t.Errorf("CVSSv4Score = %v, want 0.0", *patch.CVSSv4Score)
	}
}

func TestParseAdvisory_CVSSFallbackZeroScore(t *testing.T) {
	t.Parallel()

	// Test the fallback path: top-level cvss field (no version distinction).
	cveID := "CVE-2024-00002"
	rec := ghsaAdvisory{
		GHSAID:      "GHSA-test-0000-0002",
		CVEID:       &cveID,
		Severity:    "NONE",
		Summary:     "No impact fallback",
		PublishedAt: "2024-01-01T00:00:00Z",
		UpdatedAt:   "2024-01-01T00:00:00Z",
		CVSS: &ghsaCVSSEntry{
			Score:        0.0,
			VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
		},
	}

	patch := parseAdvisory(rec)
	if patch == nil {
		t.Fatal("parseAdvisory returned nil")
	}
	if patch.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score is nil; fallback 0.0 score was rejected")
	}
	if *patch.CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %v, want 0.0", *patch.CVSSv3Score)
	}
}
