// ABOUTME: Unit tests for the KEV feed adapter's pure parse/convert functions.
// ABOUTME: Covers parseKEV streaming parser, recordToPatch conversion, and extractCWEs helper.
package kev

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestParseKEV_FullCatalog(t *testing.T) {
	t.Parallel()

	body := `{
		"title": "CISA KEV Catalog",
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1111",
				"vendorProject": "Acme",
				"product": "Widget",
				"vulnerabilityName": "Acme Widget RCE",
				"dateAdded": "2024-08-01",
				"shortDescription": "Remote code execution in Widget",
				"requiredAction": "Apply update",
				"dueDate": "2024-09-01",
				"knownRansomwareCampaignUse": "Known",
				"notes": "",
				"cwes": ["CWE-78"]
			},
			{
				"cveID": "CVE-2024-2222",
				"vendorProject": "Beta Corp",
				"product": "Gadget",
				"vulnerabilityName": "Beta Gadget SQLi",
				"dateAdded": "2024-09-02",
				"shortDescription": "SQL injection in Gadget",
				"requiredAction": "Apply update",
				"dueDate": "2024-10-02",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": "Patch available"
			}
		]
	}`

	patches, catalogVersion, dateReleased, err := parseKEV(strings.NewReader(body), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogVersion != "2024.09.03" {
		t.Errorf("catalogVersion = %q, want %q", catalogVersion, "2024.09.03")
	}
	if dateReleased != "2024-09-03" {
		t.Errorf("dateReleased = %q, want %q", dateReleased, "2024-09-03")
	}
	if len(patches) != 2 {
		t.Fatalf("len(patches) = %d, want 2", len(patches))
	}
	if patches[0].CVEID != "CVE-2024-1111" {
		t.Errorf("patches[0].CVEID = %q, want %q", patches[0].CVEID, "CVE-2024-1111")
	}
	if patches[1].CVEID != "CVE-2024-2222" {
		t.Errorf("patches[1].CVEID = %q, want %q", patches[1].CVEID, "CVE-2024-2222")
	}
}

func TestParseKEV_ShortCircuit(t *testing.T) {
	t.Parallel()

	body := `{
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1111",
				"dateAdded": "2024-08-01",
				"shortDescription": "Should be skipped"
			}
		]
	}`

	patches, catalogVersion, dateReleased, err := parseKEV(strings.NewReader(body), "2024.09.03")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogVersion != "2024.09.03" {
		t.Errorf("catalogVersion = %q, want %q", catalogVersion, "2024.09.03")
	}
	if dateReleased != "2024-09-03" {
		t.Errorf("dateReleased = %q, want %q", dateReleased, "2024-09-03")
	}
	if len(patches) != 0 {
		t.Errorf("expected empty patches on short-circuit, got %d", len(patches))
	}
}

func TestParseKEV_EmptyVulnerabilities(t *testing.T) {
	t.Parallel()

	body := `{
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"vulnerabilities": []
	}`

	patches, catalogVersion, _, err := parseKEV(strings.NewReader(body), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogVersion != "2024.09.03" {
		t.Errorf("catalogVersion = %q, want %q", catalogVersion, "2024.09.03")
	}
	if len(patches) != 0 {
		t.Errorf("expected empty patches, got %d", len(patches))
	}
}

func TestParseKEV_UnknownTopLevelKeys(t *testing.T) {
	t.Parallel()

	body := `{
		"title": "CISA KEV Catalog",
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"unknownField": "some value",
		"anotherUnknown": 42,
		"nestedUnknown": {"key": "value"},
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-5555",
				"dateAdded": "2024-01-15",
				"shortDescription": "Test vuln"
			}
		]
	}`

	patches, catalogVersion, _, err := parseKEV(strings.NewReader(body), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogVersion != "2024.09.03" {
		t.Errorf("catalogVersion = %q, want %q", catalogVersion, "2024.09.03")
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}
	if patches[0].CVEID != "CVE-2024-5555" {
		t.Errorf("patches[0].CVEID = %q, want %q", patches[0].CVEID, "CVE-2024-5555")
	}
}

func TestParseKEV_EmptyCVEIDSkipped(t *testing.T) {
	t.Parallel()

	body := `{
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"vulnerabilities": [
			{
				"cveID": "",
				"dateAdded": "2024-01-15",
				"shortDescription": "Should be skipped"
			},
			{
				"cveID": "CVE-2024-9999",
				"dateAdded": "2024-01-16",
				"shortDescription": "Should be included"
			}
		]
	}`

	patches, _, _, err := parseKEV(strings.NewReader(body), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1 (empty cveID should be skipped)", len(patches))
	}
	if patches[0].CVEID != "CVE-2024-9999" {
		t.Errorf("patches[0].CVEID = %q, want %q", patches[0].CVEID, "CVE-2024-9999")
	}
}

func TestParseKEV_VulnerabilitiesBeforeVersion(t *testing.T) {
	t.Parallel()

	// When vulnerabilities appear before catalogVersion, the short-circuit
	// cannot fire (gotVersion is false), so all records are parsed.
	body := `{
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-0001",
				"dateAdded": "2024-01-01",
				"shortDescription": "First"
			}
		],
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03"
	}`

	patches, catalogVersion, _, err := parseKEV(strings.NewReader(body), "2024.09.03")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogVersion != "2024.09.03" {
		t.Errorf("catalogVersion = %q, want %q", catalogVersion, "2024.09.03")
	}
	// Even though storedVersion matches, vulnerabilities came first so
	// gotVersion was false when the array was encountered → records are parsed.
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1 (vulnerabilities before catalogVersion)", len(patches))
	}
}

func TestRecordToPatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rec   kevRecord
		check func(t *testing.T, p *feed.CanonicalPatch)
	}{
		{
			name: "all fields populated",
			rec: kevRecord{
				CVEID:            "CVE-2024-1234",
				VendorProject:    "Acme",
				Product:          "Widget",
				DateAdded:        "2024-06-15",
				ShortDescription: "Remote code execution in Widget",
				CWEs:             json.RawMessage(`["CWE-78","CWE-79"]`),
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.CVEID != "CVE-2024-1234" {
					t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2024-1234")
				}
				if p.SourceID != "CVE-2024-1234" {
					t.Errorf("SourceID = %q, want %q", p.SourceID, "CVE-2024-1234")
				}
				if p.InCISAKEV == nil || !*p.InCISAKEV {
					t.Error("InCISAKEV should be true")
				}
				if p.ExploitAvailable == nil || !*p.ExploitAvailable {
					t.Error("ExploitAvailable should be true")
				}
				if p.DatePublished == nil {
					t.Fatal("DatePublished should not be nil")
				}
				if p.DatePublished.Year() != 2024 || p.DatePublished.Month() != 6 || p.DatePublished.Day() != 15 {
					t.Errorf("DatePublished = %v, want 2024-06-15", p.DatePublished)
				}
				if p.DateModified == nil {
					t.Fatal("DateModified should not be nil")
				}
				if !p.DateModified.Equal(*p.DatePublished) {
					t.Errorf("DateModified = %v, want same as DatePublished %v", p.DateModified, p.DatePublished)
				}
				if p.DescriptionPrimary == nil {
					t.Fatal("DescriptionPrimary should not be nil")
				}
				if *p.DescriptionPrimary != "Remote code execution in Widget" {
					t.Errorf("DescriptionPrimary = %q, want %q", *p.DescriptionPrimary, "Remote code execution in Widget")
				}
				if len(p.CWEIDs) != 2 {
					t.Fatalf("len(CWEIDs) = %d, want 2", len(p.CWEIDs))
				}
				if p.CWEIDs[0] != "CWE-78" || p.CWEIDs[1] != "CWE-79" {
					t.Errorf("CWEIDs = %v, want [CWE-78, CWE-79]", p.CWEIDs)
				}
			},
		},
		{
			name: "empty cveID returns nil",
			rec: kevRecord{
				CVEID:            "",
				ShortDescription: "Should be skipped",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p != nil {
					t.Errorf("expected nil for empty cveID, got %+v", p)
				}
			},
		},
		{
			name: "empty shortDescription yields nil DescriptionPrimary",
			rec: kevRecord{
				CVEID:            "CVE-2023-0001",
				DateAdded:        "2023-01-01",
				ShortDescription: "",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.DescriptionPrimary != nil {
					t.Errorf("DescriptionPrimary should be nil for empty description, got %q", *p.DescriptionPrimary)
				}
			},
		},
		{
			name: "missing dateAdded yields nil dates",
			rec: kevRecord{
				CVEID:            "CVE-2023-0002",
				ShortDescription: "No date record",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.DatePublished != nil {
					t.Errorf("DatePublished should be nil when dateAdded is empty, got %v", p.DatePublished)
				}
				if p.DateModified != nil {
					t.Errorf("DateModified should be nil when dateAdded is empty, got %v", p.DateModified)
				}
			},
		},
		{
			name: "no cwes field yields nil CWEIDs",
			rec: kevRecord{
				CVEID:     "CVE-2023-0003",
				DateAdded: "2023-03-15",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.CWEIDs != nil {
					t.Errorf("CWEIDs should be nil when cwes absent, got %v", p.CWEIDs)
				}
			},
		},
		{
			name: "null cwes field yields nil CWEIDs",
			rec: kevRecord{
				CVEID:     "CVE-2023-0004",
				DateAdded: "2023-04-15",
				CWEs:      json.RawMessage(`null`),
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.CWEIDs != nil {
					t.Errorf("CWEIDs should be nil when cwes is null, got %v", p.CWEIDs)
				}
			},
		},
		{
			name: "vendor enrichment populated",
			rec: kevRecord{
				CVEID:                      "CVE-2024-5555",
				VendorProject:              "Acme",
				Product:                    "Widget",
				DateAdded:                  "2024-06-15",
				ShortDescription:           "RCE in Widget",
				RequiredAction:             "Apply update per vendor instructions",
				DueDate:                    "2024-07-15",
				KnownRansomwareCampaignUse: "Known",
				Notes:                      "Patch available from vendor",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.VendorEnrichment == nil {
					t.Fatal("VendorEnrichment should not be nil")
				}
				if p.VendorEnrichment.VendorSeverity != nil {
					t.Error("KEV does not set VendorSeverity")
				}
				if p.VendorEnrichment.VendorFixState != nil {
					t.Error("KEV does not set VendorFixState")
				}

				var data map[string]any
				if err := json.Unmarshal(p.VendorEnrichment.Data, &data); err != nil {
					t.Fatalf("unmarshal enrichment data: %v", err)
				}
				if data["required_action"] != "Apply update per vendor instructions" {
					t.Errorf("required_action = %v, want %q", data["required_action"], "Apply update per vendor instructions")
				}
				if data["due_date"] != "2024-07-15" {
					t.Errorf("due_date = %v, want %q", data["due_date"], "2024-07-15")
				}
				if data["ransomware_use"] != true {
					t.Errorf("ransomware_use = %v, want true", data["ransomware_use"])
				}
				if data["vendor_project"] != "Acme" {
					t.Errorf("vendor_project = %v, want %q", data["vendor_project"], "Acme")
				}
				if data["product"] != "Widget" {
					t.Errorf("product = %v, want %q", data["product"], "Widget")
				}
				if data["notes"] != "Patch available from vendor" {
					t.Errorf("notes = %v, want %q", data["notes"], "Patch available from vendor")
				}
			},
		},
		{
			name: "InCISAKEV and ExploitAvailable always true",
			rec: kevRecord{
				CVEID:     "CVE-2024-7777",
				DateAdded: "2024-07-01",
			},
			check: func(t *testing.T, p *feed.CanonicalPatch) {
				t.Helper()
				if p == nil {
					t.Fatal("expected non-nil patch")
				}
				if p.InCISAKEV == nil {
					t.Fatal("InCISAKEV should not be nil")
				}
				if !*p.InCISAKEV {
					t.Error("InCISAKEV should be true for all KEV records")
				}
				if p.ExploitAvailable == nil {
					t.Fatal("ExploitAvailable should not be nil")
				}
				if !*p.ExploitAvailable {
					t.Error("ExploitAvailable should be true for all KEV records")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := recordToPatch(tc.rec)
			tc.check(t, p)
		})
	}
}

func TestRecordToPatch_NullByteStripping(t *testing.T) {
	t.Parallel()

	rec := kevRecord{
		CVEID:            "CVE-2024\x00-8888",
		VendorProject:    "Acme",
		Product:          "Widget",
		DateAdded:        "2024-06-15",
		ShortDescription: "Remote\x00 code execution",
		CWEs:             json.RawMessage(`["CWE-\u000078"]`),
	}

	p := recordToPatch(rec)
	if p == nil {
		t.Fatal("expected non-nil patch")
	}

	if strings.Contains(p.CVEID, "\x00") {
		t.Errorf("CVEID contains null byte: %q", p.CVEID)
	}
	if p.CVEID != "CVE-2024-8888" {
		t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2024-8888")
	}

	if strings.Contains(p.SourceID, "\x00") {
		t.Errorf("SourceID contains null byte: %q", p.SourceID)
	}

	if p.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary is nil")
	}
	if strings.Contains(*p.DescriptionPrimary, "\x00") {
		t.Errorf("DescriptionPrimary contains null byte: %q", *p.DescriptionPrimary)
	}
	if *p.DescriptionPrimary != "Remote code execution" {
		t.Errorf("DescriptionPrimary = %q, want %q", *p.DescriptionPrimary, "Remote code execution")
	}

	if len(p.CWEIDs) != 1 {
		t.Fatalf("CWEIDs len = %d, want 1", len(p.CWEIDs))
	}
	if strings.Contains(p.CWEIDs[0], "\x00") {
		t.Errorf("CWEIDs[0] contains null byte: %q", p.CWEIDs[0])
	}
	if p.CWEIDs[0] != "CWE-78" {
		t.Errorf("CWEIDs[0] = %q, want %q", p.CWEIDs[0], "CWE-78")
	}
}

func TestExtractCWEs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
		want []string
	}{
		{
			name: "nil raw returns nil",
			raw:  nil,
			want: nil,
		},
		{
			name: "empty raw returns nil",
			raw:  json.RawMessage(``),
			want: nil,
		},
		{
			name: "null literal returns nil",
			raw:  json.RawMessage(`null`),
			want: nil,
		},
		{
			name: "valid array",
			raw:  json.RawMessage(`["CWE-78","CWE-79","CWE-89"]`),
			want: []string{"CWE-78", "CWE-79", "CWE-89"},
		},
		{
			name: "single element array",
			raw:  json.RawMessage(`["CWE-200"]`),
			want: []string{"CWE-200"},
		},
		{
			name: "empty strings filtered out",
			raw:  json.RawMessage(`["CWE-78","","CWE-89",""]`),
			want: []string{"CWE-78", "CWE-89"},
		},
		{
			name: "all empty strings yields empty slice",
			raw:  json.RawMessage(`["",""]`),
			want: []string{},
		},
		{
			name: "empty array",
			raw:  json.RawMessage(`[]`),
			want: []string{},
		},
		{
			name: "null bytes stripped from values",
			raw:  json.RawMessage(`["CWE-\u000078","CWE-89"]`),
			want: []string{"CWE-78", "CWE-89"},
		},
		{
			name: "invalid JSON returns nil",
			raw:  json.RawMessage(`{not valid json`),
			want: nil,
		},
		{
			name: "wrong type returns nil",
			raw:  json.RawMessage(`{"cwe": "CWE-78"}`),
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractCWEs(tc.raw)

			if tc.want == nil {
				if got != nil {
					t.Errorf("extractCWEs() = %v, want nil", got)
				}
				return
			}

			if len(got) != len(tc.want) {
				t.Fatalf("extractCWEs() len = %d, want %d; got %v", len(got), len(tc.want), got)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("extractCWEs()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestParseKEV_RecordDecodeErrorIsFatal(t *testing.T) {
	t.Parallel()

	// KEV records that fail to decode are fatal (unlike NVD which skips them).
	// Inject a non-object value in the vulnerabilities array to trigger a
	// decode error on the record struct.
	body := `{
		"catalogVersion": "2024.09.03",
		"dateReleased": "2024-09-03",
		"vulnerabilities": [
			"this is not a valid JSON object for a kevRecord"
		]
	}`

	_, _, _, err := parseKEV(strings.NewReader(body), "")
	if err == nil {
		t.Fatal("expected error for malformed record in vulnerabilities array, got nil")
	}
	if !strings.Contains(err.Error(), "decode record") {
		t.Errorf("error = %q, want it to contain 'decode record'", err.Error())
	}
}

func TestRecordToPatch_DateAddedParsedCorrectly(t *testing.T) {
	t.Parallel()

	rec := kevRecord{
		CVEID:     "CVE-2024-3333",
		DateAdded: "2024-07-22",
	}
	p := recordToPatch(rec)
	if p == nil {
		t.Fatal("expected non-nil patch")
	}
	if p.DatePublished == nil {
		t.Fatal("DatePublished should not be nil")
	}
	if p.DatePublished.Year() != 2024 || p.DatePublished.Month() != 7 || p.DatePublished.Day() != 22 {
		t.Errorf("DatePublished = %v, want 2024-07-22", p.DatePublished)
	}
	if p.DateModified == nil {
		t.Fatal("DateModified should not be nil")
	}
	if !p.DateModified.Equal(*p.DatePublished) {
		t.Errorf("DateModified = %v, should equal DatePublished %v", p.DateModified, p.DatePublished)
	}
}

// --- Fetch-level integration tests (httptest + redirectTransport) ---

// redirectTransport intercepts outbound requests and rewrites their scheme/host
// to point at the httptest server. This lets us test Fetch end-to-end without
// modifying the hardcoded feedURL const.
type redirectTransport struct {
	targetURL string
	inner     http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(rt.targetURL)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return rt.inner.RoundTrip(req)
}

// validKEVCatalog is a minimal KEV JSON catalog for Fetch tests.
const validKEVCatalog = `{
	"title": "CISA KEV Catalog",
	"catalogVersion": "2025.01.15",
	"dateReleased": "2025-01-15",
	"count": 2,
	"vulnerabilities": [
		{
			"cveID": "CVE-2025-0001",
			"vendorProject": "Acme",
			"product": "Router",
			"vulnerabilityName": "Acme Router RCE",
			"dateAdded": "2025-01-10",
			"shortDescription": "Remote code execution via crafted packet",
			"requiredAction": "Apply update",
			"dueDate": "2025-02-10",
			"knownRansomwareCampaignUse": "Unknown",
			"notes": "",
			"cwes": ["CWE-787"]
		},
		{
			"cveID": "CVE-2025-0002",
			"vendorProject": "Beta",
			"product": "Firewall",
			"vulnerabilityName": "Beta Firewall Auth Bypass",
			"dateAdded": "2025-01-12",
			"shortDescription": "Authentication bypass in admin panel",
			"requiredAction": "Apply update",
			"dueDate": "2025-02-12",
			"knownRansomwareCampaignUse": "Known",
			"notes": ""
		}
	]
}`

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validKEVCatalog))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Patches) != 2 {
		t.Fatalf("len(Patches) = %d, want 2", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-0001" {
		t.Errorf("Patches[0].CVEID = %q, want CVE-2025-0001", result.Patches[0].CVEID)
	}
	if result.Patches[1].CVEID != "CVE-2025-0002" {
		t.Errorf("Patches[1].CVEID = %q, want CVE-2025-0002", result.Patches[1].CVEID)
	}

	if result.SourceMeta.SourceName != "kev" {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, "kev")
	}

	if result.NextCursor == nil {
		t.Fatal("NextCursor should be non-nil")
	}
	var cursor Cursor
	if err := json.Unmarshal(result.NextCursor, &cursor); err != nil {
		t.Fatalf("failed to unmarshal NextCursor: %v", err)
	}
	if cursor.CatalogVersion != "2025.01.15" {
		t.Errorf("cursor.CatalogVersion = %q, want %q", cursor.CatalogVersion, "2025.01.15")
	}
	if cursor.DateReleased != "2025-01-15" {
		t.Errorf("cursor.DateReleased = %q, want %q", cursor.DateReleased, "2025-01-15")
	}
}

func TestFetch_ShortCircuit(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validKEVCatalog))
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := New(client)

	// Pass a cursor with the same catalogVersion as the served catalog.
	cursorJSON, _ := json.Marshal(Cursor{
		CatalogVersion: "2025.01.15",
		DateReleased:   "2025-01-15",
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Patches) != 0 {
		t.Fatalf("len(Patches) = %d, want 0 (short-circuit on matching catalogVersion)", len(result.Patches))
	}
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := New(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %q, want it to contain 'HTTP 500'", err.Error())
	}
}

func TestFetch_InvalidCursor(t *testing.T) {
	t.Parallel()

	// No httptest server needed — Fetch should fail on cursor parse before making a request.
	adapter := New(nil)

	_, err := adapter.Fetch(context.Background(), json.RawMessage(`{not valid json}`))
	if err == nil {
		t.Fatal("expected error for invalid cursor JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parse cursor") {
		t.Errorf("error = %q, want it to contain 'parse cursor'", err.Error())
	}
}
