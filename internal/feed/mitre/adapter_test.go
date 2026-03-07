// ABOUTME: Unit tests for the MITRE feed adapter's parse/convert functions and Fetch integration.
// ABOUTME: Covers isCVEEntry, parseCVE5, applyCVSS, cloneStrings, and Fetch with synthetic ZIP archives.
package mitre

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestIsCVEEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "valid CVE path",
			path: "cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json",
			want: true,
		},
		{
			name: "valid CVE path with 5-digit sequence",
			path: "cvelistV5-main/cves/2023/25xxx/CVE-2023-25136.json",
			want: true,
		},
		{
			name: "README at root",
			path: "README.md",
			want: false,
		},
		{
			name: "delta manifest",
			path: "cvelistV5-main/delta.json",
			want: false,
		},
		{
			name: "directory entry with trailing slash",
			path: "cvelistV5-main/cves/2024/1xxx/",
			want: false,
		},
		{
			name: "json without /cves/ segment",
			path: "cvelistV5-main/other/CVE-2024-1234.json",
			want: false,
		},
		{
			name: "json without CVE- prefix in filename",
			path: "cvelistV5-main/cves/2024/1xxx/something.json",
			want: false,
		},
		{
			name: "empty string",
			path: "",
			want: false,
		},
		{
			name: "non-json file in cves directory",
			path: "cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.txt",
			want: false,
		},
		{
			name: "cves and CVE- present but not json",
			path: "cvelistV5-main/cves/CVE-2024-1234/data.xml",
			want: false,
		},
		{
			name: "CVE- in directory name with json extension",
			path: "cvelistV5-main/cves/CVE-2024/1xxx/data.json",
			want: true, // contains /cves/, CVE-, and .json
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isCVEEntry(tc.path)
			if got != tc.want {
				t.Errorf("isCVEEntry(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestParseCVE5_MinimalValid(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {
			"cveId": "CVE-2024-0001",
			"state": "PUBLISHED"
		},
		"containers": {
			"cna": {}
		}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}
	if patch.CVEID != "CVE-2024-0001" {
		t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-0001")
	}
	if patch.SourceID != "CVE-2024-0001" {
		t.Errorf("SourceID = %q, want %q", patch.SourceID, "CVE-2024-0001")
	}
	if patch.Status != "PUBLISHED" {
		t.Errorf("Status = %q, want %q", patch.Status, "PUBLISHED")
	}
	if patch.IsWithdrawn {
		t.Error("IsWithdrawn = true, want false for PUBLISHED state")
	}
	if patch.DescriptionPrimary != nil {
		t.Errorf("DescriptionPrimary = %v, want nil", patch.DescriptionPrimary)
	}
}

func TestParseCVE5_EmptyCVEID(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {
			"cveId": "",
			"state": "PUBLISHED"
		},
		"containers": {"cna": {}}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch != nil {
		t.Errorf("expected nil patch for empty cveId, got %+v", patch)
	}
}

func TestParseCVE5_RejectedState(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {
			"cveId": "CVE-2024-9999",
			"state": "REJECTED"
		},
		"containers": {"cna": {}}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}
	if !patch.IsWithdrawn {
		t.Error("IsWithdrawn = false, want true for REJECTED state")
	}
	if patch.Status != "REJECTED" {
		t.Errorf("Status = %q, want %q", patch.Status, "REJECTED")
	}
}

func TestParseCVE5_RejectedStateCaseInsensitive(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {
			"cveId": "CVE-2024-9999",
			"state": "rejected"
		},
		"containers": {"cna": {}}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}
	if !patch.IsWithdrawn {
		t.Error("IsWithdrawn = false, want true for lowercase rejected state")
	}
}

func TestParseCVE5_Descriptions(t *testing.T) {
	t.Parallel()

	t.Run("first english description used", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0002", "state": "PUBLISHED"},
			"containers": {"cna": {
				"descriptions": [
					{"lang": "es", "value": "Descripción en español"},
					{"lang": "en", "value": "First English description"},
					{"lang": "en", "value": "Second English description"}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.DescriptionPrimary == nil {
			t.Fatal("expected non-nil DescriptionPrimary")
		}
		if *patch.DescriptionPrimary != "First English description" {
			t.Errorf("DescriptionPrimary = %q, want %q", *patch.DescriptionPrimary, "First English description")
		}
	})

	t.Run("non-english descriptions skipped when no english present", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0003", "state": "PUBLISHED"},
			"containers": {"cna": {
				"descriptions": [
					{"lang": "es", "value": "Solo español"},
					{"lang": "fr", "value": "Seulement français"}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.DescriptionPrimary != nil {
			t.Errorf("DescriptionPrimary = %v, want nil (no english descriptions)", *patch.DescriptionPrimary)
		}
	})

	t.Run("case-insensitive lang matching", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0004", "state": "PUBLISHED"},
			"containers": {"cna": {
				"descriptions": [
					{"lang": "EN", "value": "Uppercase EN tag"}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.DescriptionPrimary == nil {
			t.Fatal("expected non-nil DescriptionPrimary for uppercase EN")
		}
		if *patch.DescriptionPrimary != "Uppercase EN tag" {
			t.Errorf("DescriptionPrimary = %q, want %q", *patch.DescriptionPrimary, "Uppercase EN tag")
		}
	})
}

func TestParseCVE5_CWEDeduplication(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {"cveId": "CVE-2024-0005", "state": "PUBLISHED"},
		"containers": {"cna": {
			"problemTypes": [
				{
					"descriptions": [
						{"type": "CWE", "cweId": "CWE-79", "lang": "en"},
						{"type": "CWE", "cweId": "CWE-89", "lang": "en"}
					]
				},
				{
					"descriptions": [
						{"type": "CWE", "cweId": "CWE-79", "lang": "en"},
						{"type": "CWE", "cweId": "CWE-352", "lang": "en"}
					]
				}
			]
		}}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"CWE-79", "CWE-89", "CWE-352"}
	if len(patch.CWEIDs) != len(want) {
		t.Fatalf("CWEIDs length = %d, want %d; got %v", len(patch.CWEIDs), len(want), patch.CWEIDs)
	}
	for i, id := range want {
		if patch.CWEIDs[i] != id {
			t.Errorf("CWEIDs[%d] = %q, want %q", i, patch.CWEIDs[i], id)
		}
	}
}

func TestParseCVE5_CWETypeMustBeCWE(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {"cveId": "CVE-2024-0006", "state": "PUBLISHED"},
		"containers": {"cna": {
			"problemTypes": [
				{
					"descriptions": [
						{"type": "other", "cweId": "CWE-79", "lang": "en"},
						{"type": "CWE", "cweId": "", "lang": "en"}
					]
				}
			]
		}}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(patch.CWEIDs) != 0 {
		t.Errorf("CWEIDs = %v, want empty (type not CWE or cweId empty)", patch.CWEIDs)
	}
}

func TestParseCVE5_References(t *testing.T) {
	t.Parallel()

	t.Run("normal references with tags", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0007", "state": "PUBLISHED"},
			"containers": {"cna": {
				"references": [
					{"url": "https://example.com/advisory", "tags": ["vendor-advisory"]},
					{"url": "https://example.com/patch", "tags": ["patch", "third-party-advisory"]}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(patch.References) != 2 {
			t.Fatalf("References length = %d, want 2", len(patch.References))
		}
		if patch.References[0].URL != "https://example.com/advisory" {
			t.Errorf("References[0].URL = %q, want %q", patch.References[0].URL, "https://example.com/advisory")
		}
		if len(patch.References[0].Tags) != 1 || patch.References[0].Tags[0] != "vendor-advisory" {
			t.Errorf("References[0].Tags = %v, want [vendor-advisory]", patch.References[0].Tags)
		}
		if len(patch.References[1].Tags) != 2 {
			t.Errorf("References[1].Tags length = %d, want 2", len(patch.References[1].Tags))
		}
	})

	t.Run("empty URL skipped", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0008", "state": "PUBLISHED"},
			"containers": {"cna": {
				"references": [
					{"url": "", "tags": ["vendor-advisory"]},
					{"url": "https://example.com/valid"}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(patch.References) != 1 {
			t.Fatalf("References length = %d, want 1 (empty URL should be skipped)", len(patch.References))
		}
		if patch.References[0].URL != "https://example.com/valid" {
			t.Errorf("References[0].URL = %q, want %q", patch.References[0].URL, "https://example.com/valid")
		}
	})
}

func TestParseCVE5_AffectedCPEs(t *testing.T) {
	t.Parallel()

	t.Run("CPEs collected and deduplicated", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0009", "state": "PUBLISHED"},
			"containers": {"cna": {
				"affected": [
					{"cpes": ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"]},
					{"cpes": ["cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:other:3.0:*:*:*:*:*:*:*"]}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// "cpe:2.3:a:Vendor:Product:1.0:..." normalizes to same as "cpe:2.3:a:vendor:product:1.0:..."
		// so only 3 unique CPEs expected.
		if len(patch.AffectedCPEs) != 3 {
			t.Fatalf("AffectedCPEs length = %d, want 3; got:", len(patch.AffectedCPEs))
		}
	})

	t.Run("CPE original case preserved", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0010", "state": "PUBLISHED"},
			"containers": {"cna": {
				"affected": [
					{"cpes": ["cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"]}
				]
			}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(patch.AffectedCPEs) != 1 {
			t.Fatalf("AffectedCPEs length = %d, want 1", len(patch.AffectedCPEs))
		}
		if patch.AffectedCPEs[0].CPE != "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*" {
			t.Errorf("CPE = %q, want original case preserved", patch.AffectedCPEs[0].CPE)
		}
		if patch.AffectedCPEs[0].CPENormalized != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
			t.Errorf("CPENormalized = %q, want lowercase", patch.AffectedCPEs[0].CPENormalized)
		}
	})
}

func TestParseCVE5_FullEntry(t *testing.T) {
	t.Parallel()

	input := `{
		"cveMetadata": {
			"cveId": "CVE-2024-1234",
			"state": "PUBLISHED",
			"datePublished": "2024-03-01T12:00:00Z",
			"dateUpdated": "2024-03-15T08:30:00Z"
		},
		"containers": {
			"cna": {
				"descriptions": [
					{"lang": "en", "value": "A critical vulnerability in Widget Corp software."}
				],
				"metrics": [
					{
						"cvssV3_1": {
							"baseScore": 9.8,
							"baseSeverity": "CRITICAL",
							"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
						}
					},
					{
						"cvssV4_0": {
							"baseScore": 9.2,
							"baseSeverity": "CRITICAL",
							"vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
						}
					}
				],
				"problemTypes": [
					{
						"descriptions": [
							{"type": "CWE", "cweId": "CWE-787", "lang": "en"}
						]
					}
				],
				"references": [
					{"url": "https://widgetcorp.example/sa-2024-001", "tags": ["vendor-advisory"]}
				],
				"affected": [
					{"cpes": ["cpe:2.3:a:widgetcorp:widget:*:*:*:*:*:*:*:*"]}
				]
			}
		}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}

	if patch.CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-1234")
	}
	if patch.DatePublished == nil {
		t.Fatal("DatePublished is nil")
	}
	if patch.DatePublished.Year() != 2024 || patch.DatePublished.Month() != 3 || patch.DatePublished.Day() != 1 {
		t.Errorf("DatePublished = %v, want 2024-03-01", patch.DatePublished)
	}
	if patch.DateModified == nil {
		t.Fatal("DateModified is nil")
	}
	if patch.DateModified.Year() != 2024 || patch.DateModified.Month() != 3 || patch.DateModified.Day() != 15 {
		t.Errorf("DateModified = %v, want 2024-03-15", patch.DateModified)
	}
	if patch.DescriptionPrimary == nil || *patch.DescriptionPrimary != "A critical vulnerability in Widget Corp software." {
		t.Errorf("DescriptionPrimary = %v, want description text", patch.DescriptionPrimary)
	}
	if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 9.8 {
		t.Errorf("CVSSv3Score = %v, want 9.8", patch.CVSSv3Score)
	}
	if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3Vector = %v, want CVSS:3.1 vector", patch.CVSSv3Vector)
	}
	if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 9.2 {
		t.Errorf("CVSSv4Score = %v, want 9.2", patch.CVSSv4Score)
	}
	if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
		t.Errorf("CVSSv4Vector = %v, want CVSS:4.0 vector", patch.CVSSv4Vector)
	}
	if patch.Severity == nil || *patch.Severity != "CRITICAL" {
		t.Errorf("Severity = %v, want CRITICAL", patch.Severity)
	}
	if len(patch.CWEIDs) != 1 || patch.CWEIDs[0] != "CWE-787" {
		t.Errorf("CWEIDs = %v, want [CWE-787]", patch.CWEIDs)
	}
	if len(patch.References) != 1 {
		t.Fatalf("References length = %d, want 1", len(patch.References))
	}
	if patch.References[0].URL != "https://widgetcorp.example/sa-2024-001" {
		t.Errorf("References[0].URL = %q", patch.References[0].URL)
	}
	if len(patch.AffectedCPEs) != 1 {
		t.Fatalf("AffectedCPEs length = %d, want 1", len(patch.AffectedCPEs))
	}
}

func TestParseCVE5_NullByteStripping(t *testing.T) {
	t.Parallel()

	// Use JSON \u0000 escape to inject null bytes into string values.
	// Go's json.Decoder interprets \u0000 and produces actual null bytes in
	// Go strings, which parseCVE5 must strip via feed.StripNullBytes.
	input := `{
		"cveMetadata": {
			"cveId": "CVE-2024\u0000-7777",
			"state": "PUB\u0000LISHED",
			"datePublished": "2024-03-01T12:00:00Z",
			"dateUpdated": "2024-03-15T08:30:00Z"
		},
		"containers": {
			"cna": {
				"descriptions": [
					{"lang": "en", "value": "A vuln with\u0000 null bytes."}
				],
				"problemTypes": [
					{
						"descriptions": [
							{"type": "CWE", "cweId": "CWE\u0000-79", "lang": "en"}
						]
					}
				],
				"references": [
					{"url": "https://example\u0000.com/advisory"}
				],
				"affected": [
					{"cpes": ["cpe:2.3:a:\u0000vendor:product:1.0:*:*:*:*:*:*:*"]}
				]
			}
		}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch == nil {
		t.Fatal("expected non-nil patch")
	}

	if strings.Contains(patch.CVEID, "\x00") {
		t.Errorf("CVEID contains null byte: %q", patch.CVEID)
	}
	if patch.CVEID != "CVE-2024-7777" {
		t.Errorf("CVEID = %q, want %q", patch.CVEID, "CVE-2024-7777")
	}

	if strings.Contains(patch.SourceID, "\x00") {
		t.Errorf("SourceID contains null byte: %q", patch.SourceID)
	}

	if strings.Contains(patch.Status, "\x00") {
		t.Errorf("Status contains null byte: %q", patch.Status)
	}
	if patch.Status != "PUBLISHED" {
		t.Errorf("Status = %q, want %q", patch.Status, "PUBLISHED")
	}

	if patch.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary is nil")
	}
	if strings.Contains(*patch.DescriptionPrimary, "\x00") {
		t.Errorf("DescriptionPrimary contains null byte: %q", *patch.DescriptionPrimary)
	}
	if *patch.DescriptionPrimary != "A vuln with null bytes." {
		t.Errorf("DescriptionPrimary = %q, want %q", *patch.DescriptionPrimary, "A vuln with null bytes.")
	}

	if len(patch.CWEIDs) != 1 {
		t.Fatalf("CWEIDs len = %d, want 1", len(patch.CWEIDs))
	}
	if strings.Contains(patch.CWEIDs[0], "\x00") {
		t.Errorf("CWEIDs[0] contains null byte: %q", patch.CWEIDs[0])
	}
	if patch.CWEIDs[0] != "CWE-79" {
		t.Errorf("CWEIDs[0] = %q, want %q", patch.CWEIDs[0], "CWE-79")
	}

	if len(patch.References) != 1 {
		t.Fatalf("References len = %d, want 1", len(patch.References))
	}
	if strings.Contains(patch.References[0].URL, "\x00") {
		t.Errorf("References[0].URL contains null byte: %q", patch.References[0].URL)
	}
	if patch.References[0].URL != "https://example.com/advisory" {
		t.Errorf("References[0].URL = %q, want %q", patch.References[0].URL, "https://example.com/advisory")
	}

	if len(patch.AffectedCPEs) != 1 {
		t.Fatalf("AffectedCPEs len = %d, want 1", len(patch.AffectedCPEs))
	}
	if strings.Contains(patch.AffectedCPEs[0].CPE, "\x00") {
		t.Errorf("AffectedCPEs[0].CPE contains null byte: %q", patch.AffectedCPEs[0].CPE)
	}
	if patch.AffectedCPEs[0].CPE != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
		t.Errorf("AffectedCPEs[0].CPE = %q, want %q", patch.AffectedCPEs[0].CPE, "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	}
	if strings.Contains(patch.AffectedCPEs[0].CPENormalized, "\x00") {
		t.Errorf("AffectedCPEs[0].CPENormalized contains null byte: %q", patch.AffectedCPEs[0].CPENormalized)
	}
}

func TestParseCVE5_DateFields(t *testing.T) {
	t.Parallel()

	t.Run("missing dates are nil", func(t *testing.T) {
		t.Parallel()

		input := `{
			"cveMetadata": {"cveId": "CVE-2024-0011", "state": "PUBLISHED"},
			"containers": {"cna": {}}
		}`

		patch, err := parseCVE5(strings.NewReader(input))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if patch.DatePublished != nil {
			t.Errorf("DatePublished = %v, want nil", patch.DatePublished)
		}
		if patch.DateModified != nil {
			t.Errorf("DateModified = %v, want nil", patch.DateModified)
		}
	})
}

func TestParseCVE5_InvalidJSON(t *testing.T) {
	t.Parallel()

	_, err := parseCVE5(strings.NewReader(`{not valid json`))
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestParseCVE5_CVSSFromADPFallback(t *testing.T) {
	t.Parallel()

	// CNA has no metrics; ADP provides CVSS.
	input := `{
		"cveMetadata": {"cveId": "CVE-2024-0012", "state": "PUBLISHED"},
		"containers": {
			"cna": {},
			"adp": [
				{
					"metrics": [
						{
							"cvssV3_1": {
								"baseScore": 7.5,
								"baseSeverity": "HIGH",
								"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
							}
						}
					]
				}
			]
		}
	}`

	patch, err := parseCVE5(strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
		t.Errorf("CVSSv3Score = %v, want 7.5 (from ADP fallback)", patch.CVSSv3Score)
	}
	if patch.Severity == nil || *patch.Severity != "HIGH" {
		t.Errorf("Severity = %v, want HIGH (from ADP fallback)", patch.Severity)
	}
}

func TestApplyCVSS(t *testing.T) {
	t.Parallel()

	t.Run("v3.1 preferred over v3.0", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV30: &cve5CVSSv3{BaseScore: 5.0, BaseSeverity: "MEDIUM", VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
				CVSSV31: &cve5CVSSv3{BaseScore: 7.5, BaseSeverity: "HIGH", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Errorf("CVSSv3Score = %v, want 7.5 (v3.1 preferred)", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" {
			t.Errorf("CVSSv3Vector = %v, want CVSS:3.1 vector", patch.CVSSv3Vector)
		}
		if patch.Severity == nil || *patch.Severity != "HIGH" {
			t.Errorf("Severity = %v, want HIGH", patch.Severity)
		}
	})

	t.Run("v3.0 used when v3.1 absent", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV30: &cve5CVSSv3{BaseScore: 5.0, BaseSeverity: "MEDIUM", VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 5.0 {
			t.Errorf("CVSSv3Score = %v, want 5.0 (v3.0 fallback)", patch.CVSSv3Score)
		}
	})

	t.Run("v4.0 set independently", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV40: &cve5CVSSv4{BaseScore: 8.7, BaseSeverity: "HIGH", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.CVSSv3Score != nil {
			t.Errorf("CVSSv3Score = %v, want nil (only v4.0 provided)", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 8.7 {
			t.Errorf("CVSSv4Score = %v, want 8.7", patch.CVSSv4Score)
		}
		if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N" {
			t.Errorf("CVSSv4Vector = %v, want CVSS:4.0 vector", patch.CVSSv4Vector)
		}
	})

	t.Run("already-set scores not overwritten", func(t *testing.T) {
		t.Parallel()

		existingV3 := 6.0
		existingV3Vec := "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
		existingV4 := 7.0
		existingV4Vec := "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
		patch := &feed.CanonicalPatch{
			CVSSv3Score:  &existingV3,
			CVSSv3Vector: &existingV3Vec,
			CVSSv4Score:  &existingV4,
			CVSSv4Vector: &existingV4Vec,
		}
		metrics := []cve5MetricEntry{
			{
				CVSSV31: &cve5CVSSv3{BaseScore: 9.8, BaseSeverity: "CRITICAL", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
				CVSSV40: &cve5CVSSv4{BaseScore: 9.2, BaseSeverity: "CRITICAL", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if *patch.CVSSv3Score != 6.0 {
			t.Errorf("CVSSv3Score = %v, want 6.0 (should not be overwritten)", *patch.CVSSv3Score)
		}
		if *patch.CVSSv4Score != 7.0 {
			t.Errorf("CVSSv4Score = %v, want 7.0 (should not be overwritten)", *patch.CVSSv4Score)
		}
	})

	t.Run("zero baseScore entries accepted", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV31: &cve5CVSSv3{BaseScore: 0, BaseSeverity: "NONE", VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
				CVSSV40: &cve5CVSSv4{BaseScore: 0, BaseSeverity: "NONE", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 0.0 {
			t.Errorf("CVSSv3Score = %v, want 0.0 (zero score is valid)", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 0.0 {
			t.Errorf("CVSSv4Score = %v, want 0.0 (zero score is valid)", patch.CVSSv4Score)
		}
	})

	t.Run("severity from v4.0 only used when v3 severity is nil", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV31: &cve5CVSSv3{BaseScore: 4.3, BaseSeverity: "MEDIUM", VectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"},
				CVSSV40: &cve5CVSSv4{BaseScore: 8.7, BaseSeverity: "HIGH", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.Severity == nil || *patch.Severity != "MEDIUM" {
			t.Errorf("Severity = %v, want MEDIUM (v3 severity takes precedence)", patch.Severity)
		}
	})

	t.Run("severity from v4.0 used when v3 has no severity", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV31: &cve5CVSSv3{BaseScore: 4.3, BaseSeverity: "", VectorString: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"},
				CVSSV40: &cve5CVSSv4{BaseScore: 8.7, BaseSeverity: "HIGH", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.Severity == nil || *patch.Severity != "HIGH" {
			t.Errorf("Severity = %v, want HIGH (from v4.0, since v3 severity was empty)", patch.Severity)
		}
	})

	t.Run("empty metrics slice is no-op", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		applyCVSS(patch, nil)

		if patch.CVSSv3Score != nil {
			t.Errorf("CVSSv3Score = %v, want nil", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score != nil {
			t.Errorf("CVSSv4Score = %v, want nil", patch.CVSSv4Score)
		}
		if patch.Severity != nil {
			t.Errorf("Severity = %v, want nil", patch.Severity)
		}
	})

	t.Run("v3.0 and v4.0 in separate entries", func(t *testing.T) {
		t.Parallel()

		patch := &feed.CanonicalPatch{}
		metrics := []cve5MetricEntry{
			{
				CVSSV30: &cve5CVSSv3{BaseScore: 6.1, BaseSeverity: "MEDIUM", VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
			},
			{
				CVSSV40: &cve5CVSSv4{BaseScore: 5.3, BaseSeverity: "MEDIUM", VectorString: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"},
			},
		}

		applyCVSS(patch, metrics)

		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 6.1 {
			t.Errorf("CVSSv3Score = %v, want 6.1", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 5.3 {
			t.Errorf("CVSSv4Score = %v, want 5.3", patch.CVSSv4Score)
		}
	})
}

// --- Fetch integration tests ---

// redirectTransport rewrites all request URLs to point at the test server,
// allowing tests to intercept requests to the hardcoded bulkZIPURL constant.
type redirectTransport struct {
	target *url.URL
	inner  http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = rt.target.Scheme
	req.URL.Host = rt.target.Host
	return rt.inner.RoundTrip(req)
}

// buildMITREZip creates an in-memory ZIP archive containing the given entries.
// Each entry is a name/content pair. If fh is non-nil it is used as the file header
// (allowing control over Modified time); otherwise a default header is used.
func buildMITREZip(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		var fw io.Writer
		var err error
		if e.header != nil {
			e.header.Name = e.name
			fw, err = zw.CreateHeader(e.header)
		} else {
			fw, err = zw.Create(e.name)
		}
		if err != nil {
			t.Fatalf("zip create %s: %v", e.name, err)
		}
		if _, err := fw.Write(e.content); err != nil {
			t.Fatalf("zip write %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

type zipEntry struct {
	name    string
	content []byte
	header  *zip.FileHeader // optional; set Modified for cursor tests
}

// minimalCVE5JSON returns a minimal valid CVE 5.0 JSON for the given CVE ID.
func minimalCVE5JSON(cveID string) []byte {
	root := cve5Root{
		CVEMetadata: cve5Metadata{
			CVEID:         cveID,
			State:         "PUBLISHED",
			DatePublished: "2024-03-01T12:00:00Z",
			DateUpdated:   "2024-03-15T08:30:00Z",
		},
		Containers: cve5Containers{
			CNA: cve5CNA{
				Descriptions: []cve5Description{
					{Lang: "en", Value: "Test vulnerability in " + cveID},
				},
			},
		},
	}
	b, _ := json.Marshal(root)
	return b
}

// newTestAdapter creates an Adapter whose HTTP client redirects all requests
// to the given test server.
func newTestAdapter(ts *httptest.Server) *Adapter {
	tsURL, _ := url.Parse(ts.URL)
	client := &http.Client{
		Transport: &redirectTransport{
			target: tsURL,
			inner:  http.DefaultTransport,
		},
	}
	return New(client)
}

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	zipData := buildMITREZip(t, []zipEntry{
		{
			name:    "cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json",
			content: minimalCVE5JSON("CVE-2024-1234"),
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer ts.Close()

	adapter := newTestAdapter(ts)
	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if len(result.Patches) != 1 {
		t.Fatalf("Patches len = %d, want 1", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", result.Patches[0].CVEID, "CVE-2024-1234")
	}
	if result.SourceMeta.SourceName != "mitre" {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, "mitre")
	}
	if result.NextCursor == nil {
		t.Error("NextCursor is nil, want non-nil")
	}
}

func TestFetch_IncrementalSkipsOldEntries(t *testing.T) {
	t.Parallel()

	oldTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)

	oldHeader := &zip.FileHeader{Modified: oldTime, Method: zip.Deflate}
	newHeader := &zip.FileHeader{Modified: newTime, Method: zip.Deflate}

	zipData := buildMITREZip(t, []zipEntry{
		{
			name:    "cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
			content: minimalCVE5JSON("CVE-2024-0001"),
			header:  oldHeader,
		},
		{
			name:    "cvelistV5-main/cves/2024/0xxx/CVE-2024-0002.json",
			content: minimalCVE5JSON("CVE-2024-0002"),
			header:  newHeader,
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer ts.Close()

	// Cursor: last_modified = 2024-03-01 (between old and new entries).
	cursorTime := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	cursorJSON, _ := json.Marshal(Cursor{LastModified: cursorTime})

	adapter := newTestAdapter(ts)
	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if len(result.Patches) != 1 {
		t.Fatalf("Patches len = %d, want 1 (old entry should be skipped)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2024-0002" {
		t.Errorf("CVEID = %q, want %q", result.Patches[0].CVEID, "CVE-2024-0002")
	}
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	adapter := newTestAdapter(ts)
	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("Fetch should return error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to mention status 500", err.Error())
	}
}

func TestFetch_NonCVEEntriesSkipped(t *testing.T) {
	t.Parallel()

	zipData := buildMITREZip(t, []zipEntry{
		{
			name:    "cvelistV5-main/README.md",
			content: []byte("# CVE List V5"),
		},
		{
			name:    "cvelistV5-main/delta.json",
			content: []byte(`{"fetchTime":"2024-01-01T00:00:00Z"}`),
		},
		{
			name:    "cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json",
			content: minimalCVE5JSON("CVE-2024-1234"),
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer ts.Close()

	adapter := newTestAdapter(ts)
	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if len(result.Patches) != 1 {
		t.Fatalf("Patches len = %d, want 1 (non-CVE entries should be skipped)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", result.Patches[0].CVEID, "CVE-2024-1234")
	}
}

func TestFetch_MalformedEntrySkipped(t *testing.T) {
	t.Parallel()

	zipData := buildMITREZip(t, []zipEntry{
		{
			name:    "cvelistV5-main/cves/2024/0xxx/CVE-2024-0001.json",
			content: []byte(`{not valid json at all`),
		},
		{
			name:    "cvelistV5-main/cves/2024/1xxx/CVE-2024-1234.json",
			content: minimalCVE5JSON("CVE-2024-1234"),
		},
	})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipData)
	}))
	defer ts.Close()

	adapter := newTestAdapter(ts)
	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch returned error: %v", err)
	}

	if len(result.Patches) != 1 {
		t.Fatalf("Patches len = %d, want 1 (malformed entry should be skipped)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2024-1234" {
		t.Errorf("CVEID = %q, want %q", result.Patches[0].CVEID, "CVE-2024-1234")
	}
}
