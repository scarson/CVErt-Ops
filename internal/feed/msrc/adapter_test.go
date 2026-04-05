// ABOUTME: Unit tests for the MSRC feed adapter's parse, convert, and fetch logic.
// ABOUTME: Covers parseChangesCSV, csafToPatches, vendor enrichment, and end-to-end Fetch.
package msrc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"net/url"

	"github.com/scarson/cvert-ops/internal/feed"
)

// redirectTransport rewrites outbound request URLs to point at the test server.
// Used only in internal package tests to avoid importing testutil (which imports
// msrc, creating an import cycle).
type redirectTransport struct {
	targetURL string
	inner     http.RoundTripper
}

func (rt *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(rt.targetURL)
	req = req.Clone(req.Context())
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return rt.inner.RoundTrip(req)
}

// --- parseChangesCSV tests ---

func TestParseChangesCSV(t *testing.T) {
	t.Parallel()
	body := "\"2026/msrc_cve-2026-3909.json\",\"2026-03-18T01:00:00Z\"\n\"2026/msrc_cve-2026-21510.json\",\"2026-03-17T07:00:00Z\"\n\"2025/msrc_cve-2025-14174.json\",\"2026-03-12T07:00:00Z\"\n"
	entries, err := parseChangesCSV(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("len(entries) = %d, want 3", len(entries))
	}
	if entries[0].Path != "2026/msrc_cve-2026-3909.json" {
		t.Errorf("entries[0].Path = %q, want %q", entries[0].Path, "2026/msrc_cve-2026-3909.json")
	}
	if entries[0].Timestamp != "2026-03-18T01:00:00Z" {
		t.Errorf("entries[0].Timestamp = %q, want %q", entries[0].Timestamp, "2026-03-18T01:00:00Z")
	}
}

// --- csafToPatches tests ---

const minimalCSAFDoc = `{
  "document": {
    "title": "February 2026 Security Updates",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {
      "id": "2026-Feb",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2026-02-11T08:00:00Z",
      "current_release_date": "2026-02-13T08:00:00Z"
    }
  },
  "product_tree": {
    "branches": [{
      "category": "vendor",
      "name": "Microsoft",
      "branches": [{
        "category": "product_name",
        "name": "Windows 11",
        "product": {"product_id": "WIN11-22H2", "name": "Windows 11 Version 22H2"}
      }]
    }]
  },
  "vulnerabilities": [{
    "cve": "CVE-2026-21001",
    "title": "Windows Hyper-V RCE",
    "notes": [
      {"type": "description", "text": "A remote code execution vulnerability in Hyper-V."},
      {"type": "faq", "text": "How could an attacker exploit this?"}
    ],
    "scores": [{
      "cvss_v3": {
        "version": "3.1",
        "baseScore": 9.8,
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "products": ["WIN11-22H2"]
    }],
    "product_status": {
      "known_affected": ["WIN11-22H2"]
    },
    "remediations": [{
      "category": "vendor_fix",
      "details": "KB5034765",
      "url": "https://support.microsoft.com/kb/5034765",
      "product_ids": ["WIN11-22H2"]
    }],
    "threats": [
      {"category": "impact", "details": "Critical"},
      {"category": "exploit_status", "details": "Exploitation Less Likely"}
    ],
    "references": [
      {"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21001", "summary": "MSRC Advisory"}
    ]
  }]
}`

func TestCSAFToPatches(t *testing.T) {
	t.Parallel()

	patches, err := csafToPatchesFromJSON([]byte(minimalCSAFDoc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}

	p := patches[0]
	if p.CVEID != "CVE-2026-21001" {
		t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2026-21001")
	}
	if p.SourceID != p.CVEID {
		t.Errorf("SourceID = %q, want %q (same as CVEID)", p.SourceID, p.CVEID)
	}
	if p.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary should not be nil")
	}
	if *p.DescriptionPrimary != "A remote code execution vulnerability in Hyper-V." {
		t.Errorf("DescriptionPrimary = %q, want %q", *p.DescriptionPrimary, "A remote code execution vulnerability in Hyper-V.")
	}

	// CVSS v3
	if p.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score should not be nil")
	}
	if *p.CVSSv3Score != 9.8 {
		t.Errorf("CVSSv3Score = %v, want 9.8", *p.CVSSv3Score)
	}
	if p.CVSSv3Vector == nil {
		t.Fatal("CVSSv3Vector should not be nil")
	}
	if *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3Vector = %q", *p.CVSSv3Vector)
	}

	// Dates
	if p.DatePublished == nil {
		t.Fatal("DatePublished should not be nil")
	}
	if p.DateModified == nil {
		t.Fatal("DateModified should not be nil")
	}

	// References
	if len(p.References) != 1 {
		t.Fatalf("len(References) = %d, want 1", len(p.References))
	}
	if p.References[0].URL != "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21001" {
		t.Errorf("References[0].URL = %q", p.References[0].URL)
	}

	// Affected CPEs (product names from product tree lookup)
	if len(p.AffectedCPEs) != 1 {
		t.Fatalf("len(AffectedCPEs) = %d, want 1", len(p.AffectedCPEs))
	}
	if p.AffectedCPEs[0].CPE != "Windows 11 Version 22H2" {
		t.Errorf("AffectedCPEs[0].CPE = %q, want %q", p.AffectedCPEs[0].CPE, "Windows 11 Version 22H2")
	}
}

func TestCSAFToPatches_MultipleVulnerabilities(t *testing.T) {
	t.Parallel()

	doc := `{
  "document": {
    "title": "March 2026 Security Updates",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {
      "id": "2026-Mar",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2026-03-10T08:00:00Z",
      "current_release_date": "2026-03-12T08:00:00Z"
    }
  },
  "product_tree": {
    "branches": [{
      "category": "vendor",
      "name": "Microsoft",
      "branches": [{
        "category": "product_name",
        "name": "Office 365",
        "product": {"product_id": "O365", "name": "Microsoft Office 365"}
      }]
    }]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-30001",
      "title": "Office RCE",
      "notes": [{"type": "description", "text": "RCE in Office macro handling."}],
      "scores": [{"cvss_v3": {"version": "3.1", "baseScore": 8.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}, "products": ["O365"]}],
      "product_status": {"known_affected": ["O365"]},
      "threats": [{"category": "impact", "details": "Important"}]
    },
    {
      "cve": "CVE-2026-30002",
      "title": "Office Info Disclosure",
      "notes": [{"type": "description", "text": "Information disclosure via document parsing."}],
      "scores": [{"cvss_v3": {"version": "3.1", "baseScore": 5.5, "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"}, "products": ["O365"]}],
      "product_status": {"known_affected": ["O365"]},
      "threats": [{"category": "impact", "details": "Moderate"}]
    }
  ]
}`

	patches, err := csafToPatchesFromJSON([]byte(doc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 2 {
		t.Fatalf("len(patches) = %d, want 2", len(patches))
	}
	if patches[0].CVEID != "CVE-2026-30001" {
		t.Errorf("patches[0].CVEID = %q, want %q", patches[0].CVEID, "CVE-2026-30001")
	}
	if patches[1].CVEID != "CVE-2026-30002" {
		t.Errorf("patches[1].CVEID = %q, want %q", patches[1].CVEID, "CVE-2026-30002")
	}
}

func TestCSAFToPatches_VendorEnrichment(t *testing.T) {
	t.Parallel()

	patches, err := csafToPatchesFromJSON([]byte(minimalCSAFDoc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}

	p := patches[0]
	if p.VendorEnrichment == nil {
		t.Fatal("VendorEnrichment should not be nil")
	}

	// VendorSeverity from threats[category=impact]
	if p.VendorEnrichment.VendorSeverity == nil {
		t.Fatal("VendorSeverity should not be nil")
	}
	if *p.VendorEnrichment.VendorSeverity != "Critical" {
		t.Errorf("VendorSeverity = %q, want %q", *p.VendorEnrichment.VendorSeverity, "Critical")
	}

	// VendorFixState from remediations[category=vendor_fix]
	if p.VendorEnrichment.VendorFixState == nil {
		t.Fatal("VendorFixState should not be nil")
	}
	if *p.VendorEnrichment.VendorFixState != "Vendor Fix" {
		t.Errorf("VendorFixState = %q, want %q", *p.VendorEnrichment.VendorFixState, "Vendor Fix")
	}

	// Enrichment Data: exploitability, kb_articles, remediation_urls, product_statuses
	var data map[string]any
	if err := json.Unmarshal(p.VendorEnrichment.Data, &data); err != nil {
		t.Fatalf("unmarshal enrichment data: %v", err)
	}

	if data["exploitability"] != "Exploitation Less Likely" {
		t.Errorf("exploitability = %v, want %q", data["exploitability"], "Exploitation Less Likely")
	}

	kbArticles, ok := data["kb_articles"].([]any)
	if !ok {
		t.Fatalf("kb_articles not a slice: %T", data["kb_articles"])
	}
	if len(kbArticles) != 1 || kbArticles[0] != "KB5034765" {
		t.Errorf("kb_articles = %v, want [KB5034765]", kbArticles)
	}

	remURLs, ok := data["remediation_urls"].([]any)
	if !ok {
		t.Fatalf("remediation_urls not a slice: %T", data["remediation_urls"])
	}
	if len(remURLs) != 1 || remURLs[0] != "https://support.microsoft.com/kb/5034765" {
		t.Errorf("remediation_urls = %v, want [https://support.microsoft.com/kb/5034765]", remURLs)
	}

	prodStatuses, ok := data["product_statuses"].([]any)
	if !ok {
		t.Fatalf("product_statuses not a slice: %T", data["product_statuses"])
	}
	if len(prodStatuses) != 1 || prodStatuses[0] != "Windows 11 Version 22H2" {
		t.Errorf("product_statuses = %v, want [Windows 11 Version 22H2]", prodStatuses)
	}
}

func TestCSAFToPatches_HighestCVSSAcrossProducts(t *testing.T) {
	t.Parallel()

	doc := `{
  "document": {
    "title": "Test Multiple Scores",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {
      "id": "2026-Test",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2026-01-01T00:00:00Z",
      "current_release_date": "2026-01-02T00:00:00Z"
    }
  },
  "product_tree": {
    "branches": [{
      "category": "vendor",
      "name": "Microsoft",
      "branches": [
        {"category": "product_name", "name": "Win10", "product": {"product_id": "W10", "name": "Windows 10"}},
        {"category": "product_name", "name": "Win11", "product": {"product_id": "W11", "name": "Windows 11"}},
        {"category": "product_name", "name": "WinSrv", "product": {"product_id": "WS22", "name": "Windows Server 2022"}}
      ]
    }]
  },
  "vulnerabilities": [{
    "cve": "CVE-2026-99001",
    "title": "Multi-score vuln",
    "notes": [{"type": "description", "text": "Vuln with multiple scores."}],
    "scores": [
      {
        "cvss_v3": {"version": "3.1", "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "products": ["W10"]
      },
      {
        "cvss_v3": {"version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "products": ["W11"]
      },
      {
        "cvss_v3": {"version": "3.1", "baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "products": ["WS22"]
      }
    ],
    "product_status": {"known_affected": ["W10", "W11", "WS22"]},
    "threats": [{"category": "impact", "details": "Critical"}]
  }]
}`

	patches, err := csafToPatchesFromJSON([]byte(doc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}

	p := patches[0]
	if p.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score should not be nil")
	}
	// Must take highest score across all products: 9.8
	if *p.CVSSv3Score != 9.8 {
		t.Errorf("CVSSv3Score = %v, want 9.8 (highest across products)", *p.CVSSv3Score)
	}
	if p.CVSSv3Vector == nil {
		t.Fatal("CVSSv3Vector should not be nil")
	}
	if *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3Vector = %q, want the vector corresponding to highest score", *p.CVSSv3Vector)
	}
}

func TestCSAFToPatches_CVSSZeroIsValid(t *testing.T) {
	t.Parallel()

	// CVSS 0.0 is a valid score meaning "NONE" severity / informational.
	// It must not be discarded as "no score."
	csafJSON := `{
    "document": {
      "tracking": {"id": "CVSSZero", "initial_release_date": "2025-01-01T00:00:00Z", "current_release_date": "2025-01-01T00:00:00Z"},
      "title": "Test CVSS Zero"
    },
    "vulnerabilities": [{
      "cve": "CVE-2025-0000",
      "title": "CVSS zero test vuln",
      "scores": [{"cvss_v3": {"version": "3.1", "baseScore": 0.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}, "products": ["win11"]}],
      "notes": [{"type": "description", "text": "informational"}]
    }]
  }`

	patches, err := csafToPatchesFromJSON([]byte(csafJSON))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}
	p := patches[0]
	if p.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score should not be nil — 0.0 is a valid CVSS score")
	}
	if *p.CVSSv3Score != 0.0 {
		t.Errorf("CVSSv3Score = %v, want 0.0", *p.CVSSv3Score)
	}
	if p.CVSSv3Vector == nil {
		t.Fatal("CVSSv3Vector should not be nil when score is 0.0")
	}
	if *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N" {
		t.Errorf("CVSSv3Vector = %q", *p.CVSSv3Vector)
	}
}

// --- Fetch tests ---

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	changesCSV := `"2026/msrc_cve-2026-21001.json","2026-03-12T08:00:00Z"` + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/changes.csv"):
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(changesCSV))
		case strings.HasSuffix(r.URL.Path, ".json"):
			_, _ = w.Write([]byte(minimalCSAFDoc))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: srv.URL, inner: http.DefaultTransport},
	}
	adapter := New(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(result.Patches) != 1 {
		t.Fatalf("len(Patches) = %d, want 1", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2026-21001" {
		t.Errorf("CVEID = %q, want CVE-2026-21001", result.Patches[0].CVEID)
	}
	if result.SourceMeta.SourceName != SourceName {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, SourceName)
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor should not be nil")
	}

	var cur Cursor
	if err := json.Unmarshal(result.NextCursor, &cur); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	if cur.LastUpdated != "2026-03-12T08:00:00Z" {
		t.Errorf("cursor.LastUpdated = %q, want %q", cur.LastUpdated, "2026-03-12T08:00:00Z")
	}

	if !result.LastPage {
		t.Error("LastPage should be true for single-pass CSAF feed")
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

func TestFetch_ShortCircuit(t *testing.T) {
	t.Parallel()

	changesCSV := `"2026/msrc_cve-2026-21001.json","2026-03-12T08:00:00Z"` + "\n"

	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		switch {
		case strings.HasSuffix(r.URL.Path, "/changes.csv"):
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(changesCSV))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: srv.URL, inner: http.DefaultTransport},
	}
	adapter := New(client)

	cursorJSON, _ := json.Marshal(Cursor{
		LastUpdated: "2026-03-12T08:00:00Z",
	})

	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(result.Patches) != 0 {
		t.Errorf("len(Patches) = %d, want 0 (short-circuit)", len(result.Patches))
	}
	// Should have made the /changes.csv request but NOT any .json requests
	if requestCount.Load() != 1 {
		t.Errorf("requestCount = %d, want 1 (only /changes.csv, no .json)", requestCount.Load())
	}
}

func TestFetch_HTTPError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: srv.URL, inner: http.DefaultTransport},
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

func TestFetch_CSAFHTTPError(t *testing.T) {
	t.Parallel()

	changesCSV := `"2026/msrc_cve-2026-21001.json","2026-04-01T00:00:00Z"` + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/changes.csv"):
			w.Header().Set("Content-Type", "text/csv")
			_, _ = w.Write([]byte(changesCSV))
		case strings.HasSuffix(r.URL.Path, ".json"):
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: srv.URL, inner: http.DefaultTransport},
	}
	adapter := New(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when CSAF returns 500, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %q, want 'HTTP 500'", err.Error())
	}
}

func TestCSAFToPatches_CVSSv4(t *testing.T) {
	t.Parallel()

	doc := `{
  "document": {
    "title": "Test CVSSv4",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {"id": "2026-Test", "status": "final", "version": "1.0",
      "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-02T00:00:00Z"}
  },
  "product_tree": {"branches": [{"category": "vendor", "name": "Microsoft",
    "branches": [{"category": "product_name", "name": "Win11",
      "product": {"product_id": "W11", "name": "Windows 11"}}]}]},
  "vulnerabilities": [{
    "cve": "CVE-2026-40001",
    "title": "CVSSv4 test vuln",
    "scores": [{
      "cvss_v4": {"version": "4.0", "baseScore": 8.2, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"},
      "products": ["W11"]
    }],
    "product_status": {"known_affected": ["W11"]},
    "threats": [{"category": "impact", "details": "Important"}]
  }]
}`

	patches, err := csafToPatchesFromJSON([]byte(doc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}

	p := patches[0]
	if p.CVSSv4Score == nil {
		t.Fatal("CVSSv4Score should not be nil")
	}
	if *p.CVSSv4Score != 8.2 {
		t.Errorf("CVSSv4Score = %v, want 8.2", *p.CVSSv4Score)
	}
	if p.CVSSv4Vector == nil {
		t.Fatal("CVSSv4Vector should not be nil")
	}
	if *p.CVSSv4Vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N" {
		t.Errorf("CVSSv4Vector = %q", *p.CVSSv4Vector)
	}
	// Should not have CVSSv3
	if p.CVSSv3Score != nil {
		t.Errorf("CVSSv3Score should be nil when only CVSSv4 present, got %v", *p.CVSSv3Score)
	}
}

func TestCSAFToPatches_EmptyCVESkipped(t *testing.T) {
	t.Parallel()

	doc := `{
  "document": {
    "title": "Test",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {"id": "2026-Test", "status": "final", "version": "1.0",
      "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-02T00:00:00Z"}
  },
  "product_tree": {"branches": []},
  "vulnerabilities": [
    {"cve": "", "title": "No CVE ID"},
    {"cve": "CVE-2026-50001", "title": "Real vuln"}
  ]
}`

	patches, err := csafToPatchesFromJSON([]byte(doc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1 (empty CVE skipped)", len(patches))
	}
	if patches[0].CVEID != "CVE-2026-50001" {
		t.Errorf("CVEID = %q, want CVE-2026-50001", patches[0].CVEID)
	}
}

func TestCSAFToPatches_NoEnrichmentReturnsNil(t *testing.T) {
	t.Parallel()

	doc := `{
  "document": {
    "title": "Test",
    "type": "csaf_security_advisory",
    "publisher": {"name": "Microsoft", "namespace": "https://msrc.microsoft.com"},
    "tracking": {"id": "2026-Test", "status": "final", "version": "1.0",
      "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-02T00:00:00Z"}
  },
  "product_tree": {"branches": []},
  "vulnerabilities": [{
    "cve": "CVE-2026-60001",
    "title": "No threats or remediations",
    "scores": [{"cvss_v3": {"version": "3.1", "baseScore": 5.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}, "products": []}],
    "product_status": {"known_affected": []}
  }]
}`

	patches, err := csafToPatchesFromJSON([]byte(doc))
	if err != nil {
		t.Fatalf("csafToPatches: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("len(patches) = %d, want 1", len(patches))
	}
	if patches[0].VendorEnrichment != nil {
		t.Error("VendorEnrichment should be nil when no threats or remediations exist")
	}
}

// --- helper: parse CSAF JSON and convert to patches ---

func csafToPatchesFromJSON(data []byte) ([]feed.CanonicalPatch, error) {
	doc, err := parseCSAFDocument(data)
	if err != nil {
		return nil, err
	}
	return csafToPatches(doc), nil
}
