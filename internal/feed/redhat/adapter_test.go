// ABOUTME: Unit tests for the Red Hat Security Data API feed adapter.
// ABOUTME: Covers list/detail parsing, field mapping, vendor enrichment, and end-to-end Fetch.
package redhat

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/time/rate"
)

// --- parseListResponse tests ---

func TestParseListResponse(t *testing.T) {
	t.Parallel()

	body := `[
		{
			"CVE": "CVE-2025-0001",
			"severity": "important",
			"public_date": "2025-01-15T00:00:00Z",
			"advisories": ["RHSA-2025:0001"],
			"cvss_score": 8.8,
			"resource_url": "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-0001.json"
		},
		{
			"CVE": "CVE-2025-0002",
			"severity": "moderate",
			"public_date": "2025-01-16T00:00:00Z",
			"advisories": [],
			"cvss_score": 5.5,
			"resource_url": "https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2025-0002.json"
		}
	]`

	entries, err := parseListResponse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].CVE != "CVE-2025-0001" {
		t.Errorf("entries[0].CVE = %q, want %q", entries[0].CVE, "CVE-2025-0001")
	}
	if entries[1].CVE != "CVE-2025-0002" {
		t.Errorf("entries[1].CVE = %q, want %q", entries[1].CVE, "CVE-2025-0002")
	}
}

// --- parseDetailResponse tests ---

const fullDetailJSON = `{
	"name": "CVE-2025-0001",
	"threat_severity": "Important",
	"public_date": "2025-01-15T00:00:00Z",
	"cwe": "CWE-79",
	"cvss3": {
		"cvss3_base_score": "8.8",
		"cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
	},
	"details": ["A cross-site scripting vulnerability was found in the widget component."],
	"references": ["https://example.com/advisory"],
	"bugzilla": {
		"id": "2345678",
		"url": "https://bugzilla.redhat.com/show_bug.cgi?id=2345678",
		"description": "CVE-2025-0001 xss in widget"
	},
	"affected_release": [
		{
			"product_name": "Red Hat Enterprise Linux 9",
			"advisory": "RHSA-2025:0001",
			"cpe": "cpe:/a:redhat:enterprise_linux:9",
			"package": "widget-1.2.3-4.el9"
		}
	],
	"package_state": [
		{
			"product_name": "Red Hat Enterprise Linux 8",
			"fix_state": "Will not fix",
			"cpe": "cpe:/a:redhat:enterprise_linux:8",
			"package_name": "widget"
		}
	],
	"mitigation": {"value": "Disable the widget feature"},
	"upstream_fix": "widget 1.3.0"
}`

func TestParseDetailResponse(t *testing.T) {
	t.Parallel()

	detail, err := parseDetailResponse(strings.NewReader(fullDetailJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if detail.Name != "CVE-2025-0001" {
		t.Errorf("Name = %q, want %q", detail.Name, "CVE-2025-0001")
	}
	if detail.ThreatSeverity != "Important" {
		t.Errorf("ThreatSeverity = %q, want %q", detail.ThreatSeverity, "Important")
	}
	if detail.PublicDate != "2025-01-15T00:00:00Z" {
		t.Errorf("PublicDate = %q, want %q", detail.PublicDate, "2025-01-15T00:00:00Z")
	}
	if detail.CWE != "CWE-79" {
		t.Errorf("CWE = %q, want %q", detail.CWE, "CWE-79")
	}
	if detail.CVSS3 == nil {
		t.Fatal("CVSS3 should not be nil")
	}
	if detail.CVSS3.BaseScore != "8.8" {
		t.Errorf("CVSS3.BaseScore = %q, want %q", detail.CVSS3.BaseScore, "8.8")
	}
	if detail.CVSS3.ScoringVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSS3.ScoringVector = %q", detail.CVSS3.ScoringVector)
	}
	if len(detail.Details) != 1 {
		t.Fatalf("len(Details) = %d, want 1", len(detail.Details))
	}
	if len(detail.References) != 1 {
		t.Fatalf("len(References) = %d, want 1", len(detail.References))
	}
	if detail.Bugzilla == nil {
		t.Fatal("Bugzilla should not be nil")
	}
	if detail.Bugzilla.URL != "https://bugzilla.redhat.com/show_bug.cgi?id=2345678" {
		t.Errorf("Bugzilla.URL = %q", detail.Bugzilla.URL)
	}
	if len(detail.AffectedRelease) != 1 {
		t.Fatalf("len(AffectedRelease) = %d, want 1", len(detail.AffectedRelease))
	}
	if detail.AffectedRelease[0].CPE != "cpe:/a:redhat:enterprise_linux:9" {
		t.Errorf("AffectedRelease[0].CPE = %q", detail.AffectedRelease[0].CPE)
	}
	if len(detail.PackageState) != 1 {
		t.Fatalf("len(PackageState) = %d, want 1", len(detail.PackageState))
	}
	if detail.PackageState[0].FixState != "Will not fix" {
		t.Errorf("PackageState[0].FixState = %q", detail.PackageState[0].FixState)
	}
	if detail.Mitigation == nil {
		t.Fatal("Mitigation should not be nil")
	}
	if detail.Mitigation.Value != "Disable the widget feature" {
		t.Errorf("Mitigation.Value = %q", detail.Mitigation.Value)
	}
	if detail.UpstreamFix != "widget 1.3.0" {
		t.Errorf("UpstreamFix = %q", detail.UpstreamFix)
	}
}

// --- detailToPatch tests ---

func TestDetailToPatch(t *testing.T) {
	t.Parallel()

	detail := detailRecord{
		Name:           "CVE-2025-0001",
		ThreatSeverity: "Important",
		PublicDate:     "2025-01-15T00:00:00Z",
		CWE:            "CWE-79",
		CVSS3: &cvss3Info{
			BaseScore:     "8.8",
			ScoringVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
		},
		Details:    []string{"A cross-site scripting vulnerability was found."},
		References: []string{"https://example.com/advisory"},
		Bugzilla: &bugzillaInfo{
			ID:          "2345678",
			URL:         "https://bugzilla.redhat.com/show_bug.cgi?id=2345678",
			Description: "CVE-2025-0001 xss in widget",
		},
		AffectedRelease: []affectedRelease{
			{
				ProductName: "Red Hat Enterprise Linux 9",
				Advisory:    "RHSA-2025:0001",
				CPE:         "cpe:/a:redhat:enterprise_linux:9",
				Package:     "widget-1.2.3-4.el9",
			},
		},
		PackageState: []packageState{
			{
				ProductName: "Red Hat Enterprise Linux 8",
				FixState:    "Will not fix",
				CPE:         "cpe:/a:redhat:enterprise_linux:8",
				PackageName: "widget",
			},
		},
	}

	p := detailToPatch(detail)
	if p.CVEID != "CVE-2025-0001" {
		t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2025-0001")
	}
	if p.SourceID != p.CVEID {
		t.Errorf("SourceID = %q, want %q (same as CVEID)", p.SourceID, p.CVEID)
	}
	if p.DescriptionPrimary == nil {
		t.Fatal("DescriptionPrimary should not be nil")
	}
	if *p.DescriptionPrimary != "A cross-site scripting vulnerability was found." {
		t.Errorf("DescriptionPrimary = %q", *p.DescriptionPrimary)
	}
	if p.DatePublished == nil {
		t.Fatal("DatePublished should not be nil")
	}
	if p.DatePublished.Year() != 2025 || p.DatePublished.Month() != 1 || p.DatePublished.Day() != 15 {
		t.Errorf("DatePublished = %v, want 2025-01-15", p.DatePublished)
	}

	// CVSS
	if p.CVSSv3Score == nil {
		t.Fatal("CVSSv3Score should not be nil")
	}
	if *p.CVSSv3Score != 8.8 {
		t.Errorf("CVSSv3Score = %v, want 8.8", *p.CVSSv3Score)
	}
	if p.CVSSv3Vector == nil {
		t.Fatal("CVSSv3Vector should not be nil")
	}
	if *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" {
		t.Errorf("CVSSv3Vector = %q", *p.CVSSv3Vector)
	}

	// CWE
	if len(p.CWEIDs) != 1 {
		t.Fatalf("len(CWEIDs) = %d, want 1", len(p.CWEIDs))
	}
	if p.CWEIDs[0] != "CWE-79" {
		t.Errorf("CWEIDs[0] = %q, want %q", p.CWEIDs[0], "CWE-79")
	}

	// References: bugzilla.url + references[]
	if len(p.References) != 2 {
		t.Fatalf("len(References) = %d, want 2", len(p.References))
	}
	// Bugzilla URL should be first
	if p.References[0].URL != "https://bugzilla.redhat.com/show_bug.cgi?id=2345678" {
		t.Errorf("References[0].URL = %q, want bugzilla URL", p.References[0].URL)
	}
	if p.References[1].URL != "https://example.com/advisory" {
		t.Errorf("References[1].URL = %q, want example advisory URL", p.References[1].URL)
	}

	// Affected CPEs from affected_release[].cpe
	if len(p.AffectedCPEs) != 1 {
		t.Fatalf("len(AffectedCPEs) = %d, want 1", len(p.AffectedCPEs))
	}
	if p.AffectedCPEs[0].CPE != "cpe:/a:redhat:enterprise_linux:9" {
		t.Errorf("AffectedCPEs[0].CPE = %q", p.AffectedCPEs[0].CPE)
	}
}

func TestDetailToPatch_VendorEnrichment(t *testing.T) {
	t.Parallel()

	detail := detailRecord{
		Name:           "CVE-2025-0001",
		ThreatSeverity: "Important",
		PublicDate:     "2025-01-15T00:00:00Z",
		Bugzilla: &bugzillaInfo{
			ID:          "2345678",
			URL:         "https://bugzilla.redhat.com/show_bug.cgi?id=2345678",
			Description: "CVE-2025-0001 xss in widget",
		},
		AffectedRelease: []affectedRelease{
			{
				ProductName: "RHEL 9",
				Advisory:    "RHSA-2025:0001",
				CPE:         "cpe:/a:redhat:enterprise_linux:9",
				Package:     "widget-1.2.3-4.el9",
			},
		},
		PackageState: []packageState{
			{
				ProductName: "RHEL 8",
				FixState:    "Affected",
				CPE:         "cpe:/a:redhat:enterprise_linux:8",
				PackageName: "widget",
			},
		},
		Mitigation:  &mitigationInfo{Value: "Disable the widget feature"},
		UpstreamFix: "widget 1.3.0",
	}

	p := detailToPatch(detail)
	if p.VendorEnrichment == nil {
		t.Fatal("VendorEnrichment should not be nil")
	}

	// VendorSeverity from threat_severity
	if p.VendorEnrichment.VendorSeverity == nil {
		t.Fatal("VendorSeverity should not be nil")
	}
	if *p.VendorEnrichment.VendorSeverity != "Important" {
		t.Errorf("VendorSeverity = %q, want %q", *p.VendorEnrichment.VendorSeverity, "Important")
	}

	// VendorFixState from worst-case package_state
	if p.VendorEnrichment.VendorFixState == nil {
		t.Fatal("VendorFixState should not be nil")
	}
	if *p.VendorEnrichment.VendorFixState != "Affected" {
		t.Errorf("VendorFixState = %q, want %q", *p.VendorEnrichment.VendorFixState, "Affected")
	}

	// Enrichment data
	var data map[string]any
	if err := json.Unmarshal(p.VendorEnrichment.Data, &data); err != nil {
		t.Fatalf("unmarshal enrichment data: %v", err)
	}

	// Check bugzilla
	bz, ok := data["bugzilla"].(map[string]any)
	if !ok {
		t.Fatalf("bugzilla not a map: %T", data["bugzilla"])
	}
	if bz["url"] != "https://bugzilla.redhat.com/show_bug.cgi?id=2345678" {
		t.Errorf("bugzilla.url = %v", bz["url"])
	}

	// Check mitigation
	if data["mitigation"] != "Disable the widget feature" {
		t.Errorf("mitigation = %v, want %q", data["mitigation"], "Disable the widget feature")
	}

	// Check upstream_fix
	if data["upstream_fix"] != "widget 1.3.0" {
		t.Errorf("upstream_fix = %v, want %q", data["upstream_fix"], "widget 1.3.0")
	}
}

func TestDetailToPatch_WorstCaseFixState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		states     []string
		wantWorst  string
	}{
		{
			name:      "Affected wins over all",
			states:    []string{"Not affected", "Will not fix", "Affected", "Under investigation"},
			wantWorst: "Affected",
		},
		{
			name:      "Will not fix wins over lower",
			states:    []string{"Not affected", "Will not fix", "Fix deferred"},
			wantWorst: "Will not fix",
		},
		{
			name:      "Fix deferred wins over lower",
			states:    []string{"Under investigation", "Fix deferred", "Not affected"},
			wantWorst: "Fix deferred",
		},
		{
			name:      "Under investigation wins over Not affected",
			states:    []string{"Not affected", "Under investigation"},
			wantWorst: "Under investigation",
		},
		{
			name:      "single Not affected",
			states:    []string{"Not affected"},
			wantWorst: "Not affected",
		},
		{
			name:      "unknown state treated as unknown",
			states:    []string{"Not affected", "Something new"},
			wantWorst: "Something new",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var states []packageState
			for _, s := range tc.states {
				states = append(states, packageState{
					ProductName: "Some Product",
					FixState:    s,
					CPE:         "cpe:/a:redhat:test",
					PackageName: "test-pkg",
				})
			}

			detail := detailRecord{
				Name:         "CVE-2025-9999",
				PackageState: states,
			}

			p := detailToPatch(detail)
			if p.VendorEnrichment == nil {
				t.Fatal("VendorEnrichment should not be nil")
			}
			if p.VendorEnrichment.VendorFixState == nil {
				t.Fatal("VendorFixState should not be nil")
			}
			if *p.VendorEnrichment.VendorFixState != tc.wantWorst {
				t.Errorf("VendorFixState = %q, want %q", *p.VendorEnrichment.VendorFixState, tc.wantWorst)
			}
		})
	}
}

func TestDetailToPatch_CVSSParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		cvss3      *cvss3Info
		wantScore  *float64
		wantVector *string
	}{
		{
			name: "valid score and vector",
			cvss3: &cvss3Info{
				BaseScore:     "7.5",
				ScoringVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
			wantScore:  floatPtr(7.5),
			wantVector: strPtr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
		},
		{
			name:       "nil cvss3",
			cvss3:      nil,
			wantScore:  nil,
			wantVector: nil,
		},
		{
			name: "unparseable score",
			cvss3: &cvss3Info{
				BaseScore:     "not-a-number",
				ScoringVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
			wantScore:  nil,
			wantVector: nil,
		},
		{
			name: "empty score string",
			cvss3: &cvss3Info{
				BaseScore:     "",
				ScoringVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			},
			wantScore:  nil,
			wantVector: nil,
		},
		{
			name: "score of 10.0",
			cvss3: &cvss3Info{
				BaseScore:     "10.0",
				ScoringVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			},
			wantScore:  floatPtr(10.0),
			wantVector: strPtr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			detail := detailRecord{
				Name:  "CVE-2025-0001",
				CVSS3: tc.cvss3,
			}

			p := detailToPatch(detail)

			if tc.wantScore == nil {
				if p.CVSSv3Score != nil {
					t.Errorf("CVSSv3Score = %v, want nil", *p.CVSSv3Score)
				}
			} else {
				if p.CVSSv3Score == nil {
					t.Fatal("CVSSv3Score should not be nil")
				}
				if *p.CVSSv3Score != *tc.wantScore {
					t.Errorf("CVSSv3Score = %v, want %v", *p.CVSSv3Score, *tc.wantScore)
				}
			}

			if tc.wantVector == nil {
				if p.CVSSv3Vector != nil {
					t.Errorf("CVSSv3Vector = %q, want nil", *p.CVSSv3Vector)
				}
			} else {
				if p.CVSSv3Vector == nil {
					t.Fatal("CVSSv3Vector should not be nil")
				}
				if *p.CVSSv3Vector != *tc.wantVector {
					t.Errorf("CVSSv3Vector = %q, want %q", *p.CVSSv3Vector, *tc.wantVector)
				}
			}
		})
	}
}

func TestDetailToPatch_MissingFields(t *testing.T) {
	t.Parallel()

	// Minimal detail: only name field
	detail := detailRecord{
		Name: "CVE-2025-0001",
	}

	p := detailToPatch(detail)
	if p.CVEID != "CVE-2025-0001" {
		t.Errorf("CVEID = %q, want %q", p.CVEID, "CVE-2025-0001")
	}
	if p.SourceID != p.CVEID {
		t.Errorf("SourceID = %q, want %q (same as CVEID)", p.SourceID, p.CVEID)
	}
	if p.DescriptionPrimary != nil {
		t.Errorf("DescriptionPrimary should be nil for missing details, got %q", *p.DescriptionPrimary)
	}
	if p.CVSSv3Score != nil {
		t.Errorf("CVSSv3Score should be nil, got %v", *p.CVSSv3Score)
	}
	if p.CVSSv3Vector != nil {
		t.Errorf("CVSSv3Vector should be nil, got %q", *p.CVSSv3Vector)
	}
	if p.DatePublished != nil {
		t.Errorf("DatePublished should be nil, got %v", *p.DatePublished)
	}
	if len(p.CWEIDs) != 0 {
		t.Errorf("CWEIDs should be empty, got %v", p.CWEIDs)
	}
	if len(p.References) != 0 {
		t.Errorf("References should be empty, got %v", p.References)
	}
	if len(p.AffectedCPEs) != 0 {
		t.Errorf("AffectedCPEs should be empty, got %v", p.AffectedCPEs)
	}
}

func TestDetailToPatch_CWEChainTakesFirst(t *testing.T) {
	t.Parallel()

	detail := detailRecord{
		Name: "CVE-2025-0001",
		CWE:  "CWE-79->CWE-80",
	}

	p := detailToPatch(detail)
	if len(p.CWEIDs) != 1 {
		t.Fatalf("len(CWEIDs) = %d, want 1", len(p.CWEIDs))
	}
	if p.CWEIDs[0] != "CWE-79" {
		t.Errorf("CWEIDs[0] = %q, want %q (first in chain)", p.CWEIDs[0], "CWE-79")
	}
}

// --- Fetch integration tests ---

// redirectTransport intercepts outbound requests and rewrites their scheme/host
// to point at the httptest server.
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

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	listResp := `[
		{"CVE": "CVE-2025-0001", "severity": "important", "public_date": "2025-01-15T00:00:00Z"},
		{"CVE": "CVE-2025-0002", "severity": "moderate", "public_date": "2025-01-16T00:00:00Z"}
	]`

	detailResp1 := `{
		"name": "CVE-2025-0001",
		"threat_severity": "Important",
		"public_date": "2025-01-15T00:00:00Z",
		"details": ["XSS vulnerability"],
		"cvss3": {"cvss3_base_score": "8.8", "cvss3_scoring_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}
	}`

	detailResp2 := `{
		"name": "CVE-2025-0002",
		"threat_severity": "Moderate",
		"public_date": "2025-01-16T00:00:00Z",
		"details": ["Info disclosure"]
	}`

	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			_, _ = w.Write([]byte(listResp))
		case strings.HasSuffix(r.URL.Path, "/cve/CVE-2025-0001.json"):
			_, _ = w.Write([]byte(detailResp1))
		case strings.HasSuffix(r.URL.Path, "/cve/CVE-2025-0002.json"):
			_, _ = w.Write([]byte(detailResp2))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := newTestAdapter(client)

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
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
	if result.SourceMeta.SourceName != SourceName {
		t.Errorf("SourceName = %q, want %q", result.SourceMeta.SourceName, SourceName)
	}

	// 1 list request + 2 detail requests = 3 total
	if requestCount.Load() != 3 {
		t.Errorf("requestCount = %d, want 3", requestCount.Load())
	}

	// NextCursor should advance AfterDate even on partial page
	if result.NextCursor == nil {
		t.Fatal("NextCursor should not be nil — AfterDate must advance on last page")
	}
}

func TestFetch_DetailNotFound(t *testing.T) {
	t.Parallel()

	listResp := `[
		{"CVE": "CVE-2025-0001", "severity": "important"},
		{"CVE": "CVE-2025-0002", "severity": "moderate"}
	]`

	detailResp2 := `{
		"name": "CVE-2025-0002",
		"threat_severity": "Moderate",
		"public_date": "2025-01-16T00:00:00Z",
		"details": ["Info disclosure"]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			_, _ = w.Write([]byte(listResp))
		case strings.HasSuffix(r.URL.Path, "/cve/CVE-2025-0001.json"):
			// 404 on this detail endpoint
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, "/cve/CVE-2025-0002.json"):
			_, _ = w.Write([]byte(detailResp2))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := newTestAdapter(client)

	// Capture log output to verify the 404 warning
	var logBuf bytes.Buffer
	adapter.log = slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch should not error on 404 detail, got: %v", err)
	}
	// Only the second CVE should have a patch
	if len(result.Patches) != 1 {
		t.Fatalf("len(Patches) = %d, want 1 (404 detail skipped)", len(result.Patches))
	}
	if result.Patches[0].CVEID != "CVE-2025-0002" {
		t.Errorf("Patches[0].CVEID = %q, want CVE-2025-0002", result.Patches[0].CVEID)
	}

	// Verify warning was logged for the 404
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "detail 404") {
		t.Errorf("expected log to contain 'detail 404', got %q", logOutput)
	}
	if !strings.Contains(logOutput, "CVE-2025-0001") {
		t.Errorf("expected log to contain 'CVE-2025-0001', got %q", logOutput)
	}
}

func TestFetch_Pagination(t *testing.T) {
	t.Parallel()

	// Simulate a full page of 100 items to trigger pagination cursor
	listPage1 := make([]listEntry, 100)
	for i := range listPage1 {
		listPage1[i] = listEntry{CVE: "CVE-2025-" + padInt(i+1)}
	}
	listPage1JSON, _ := json.Marshal(listPage1)

	// Page 2 returns fewer than 100 items (end of pagination)
	listPage2 := `[{"CVE": "CVE-2025-0101"}]`

	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			page := r.URL.Query().Get("page")
			if page == "" || page == "1" {
				_, _ = w.Write(listPage1JSON)
			} else {
				_, _ = w.Write([]byte(listPage2))
			}
		case strings.Contains(r.URL.Path, "/cve/CVE-"):
			// Return minimal detail for any CVE; extract CVE ID from path
			idx := strings.LastIndex(r.URL.Path, "/cve/")
			cveID := r.URL.Path[idx+len("/cve/"):]
			cveID = strings.TrimSuffix(cveID, ".json")
			_, _ = w.Write([]byte(`{"name":"` + cveID + `","details":["test"]}`)) //nolint:gosec // G705: test httptest server, not user input
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := newTestAdapter(client)

	// First fetch: should get 100 CVEs and return a NextCursor for page 2
	result, err := adapter.Fetch(context.Background(), nil)
	if err != nil {
		t.Fatalf("Fetch page 1: %v", err)
	}
	if len(result.Patches) != 100 {
		t.Fatalf("len(Patches) page 1 = %d, want 100", len(result.Patches))
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor should not be nil for a full page (100 items)")
	}

	// Verify cursor has page 2
	var cur Cursor
	if err := json.Unmarshal(result.NextCursor, &cur); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	if cur.Page != 2 {
		t.Errorf("cursor.Page = %d, want 2", cur.Page)
	}

	// Second fetch: use returned cursor for page 2
	result2, err := adapter.Fetch(context.Background(), result.NextCursor)
	if err != nil {
		t.Fatalf("Fetch page 2: %v", err)
	}
	if len(result2.Patches) != 1 {
		t.Fatalf("len(Patches) page 2 = %d, want 1", len(result2.Patches))
	}
	// Page 2 has fewer than 100, so NextCursor should advance AfterDate
	if result2.NextCursor == nil {
		t.Fatal("NextCursor should not be nil — AfterDate must advance on last page")
	}
	var lastCur Cursor
	if err := json.Unmarshal(result2.NextCursor, &lastCur); err != nil {
		t.Fatalf("unmarshal last-page cursor: %v", err)
	}
	if lastCur.Page != 0 {
		t.Errorf("Page should be 0 (reset) on last page, got %d", lastCur.Page)
	}
}

// padInt pads an integer to 4 digits for CVE ID generation in tests.
func padInt(n int) string {
	s := ""
	if n < 10 {
		s = "000"
	} else if n < 100 {
		s = "00"
	} else if n < 1000 {
		s = "0"
	}
	return s + itoa(n)
}

// itoa converts int to string without importing strconv in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

func TestFetch_InvalidCursorDate(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("should not make HTTP request with invalid cursor date")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := newTestAdapter(client)

	cursorJSON, _ := json.Marshal(Cursor{
		AfterDate: "'; DROP TABLE cves; --",
	})

	_, err := adapter.Fetch(context.Background(), cursorJSON)
	if err == nil {
		t.Fatal("expected error for invalid cursor date, got nil")
	}
	if !strings.Contains(err.Error(), "invalid cursor date format") {
		t.Errorf("error = %q, want 'invalid cursor date format'", err.Error())
	}
}

func TestFetch_DetailHTTPError(t *testing.T) {
	t.Parallel()

	listResp := `[{"CVE": "CVE-2025-0001"}]`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			_, _ = w.Write([]byte(listResp))
		case strings.Contains(r.URL.Path, "/cve/CVE-"):
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			targetURL: ts.URL,
			inner:     http.DefaultTransport,
		},
	}
	adapter := newTestAdapter(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500 on detail, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %q, want 'HTTP 500'", err.Error())
	}
}

func TestParseDetailResponse_PolymorphicSingleObject(t *testing.T) {
	t.Parallel()

	// Red Hat API returns single object instead of array when exactly one entry exists.
	body := `{
		"name": "CVE-2025-9999",
		"threat_severity": "Moderate",
		"affected_release": {
			"product_name": "RHEL 9",
			"advisory": "RHSA-2025:9999",
			"cpe": "cpe:/a:redhat:enterprise_linux:9",
			"package": "widget-2.0-1.el9"
		},
		"package_state": {
			"product_name": "RHEL 8",
			"fix_state": "Not affected",
			"cpe": "cpe:/a:redhat:enterprise_linux:8",
			"package_name": "widget"
		}
	}`

	detail, err := parseDetailResponse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseDetailResponse: %v", err)
	}
	if len(detail.AffectedRelease) != 1 {
		t.Fatalf("len(AffectedRelease) = %d, want 1", len(detail.AffectedRelease))
	}
	if detail.AffectedRelease[0].Advisory != "RHSA-2025:9999" {
		t.Errorf("AffectedRelease[0].Advisory = %q, want %q", detail.AffectedRelease[0].Advisory, "RHSA-2025:9999")
	}
	if len(detail.PackageState) != 1 {
		t.Fatalf("len(PackageState) = %d, want 1", len(detail.PackageState))
	}
	if detail.PackageState[0].FixState != "Not affected" {
		t.Errorf("PackageState[0].FixState = %q, want %q", detail.PackageState[0].FixState, "Not affected")
	}
}

func TestDetailToPatch_NilVendorEnrichment(t *testing.T) {
	t.Parallel()

	// A detail with no enrichment data should return nil VendorEnrichment.
	detail := detailRecord{
		Name: "CVE-2025-0001",
	}

	p := detailToPatch(detail)
	if p.VendorEnrichment != nil {
		t.Error("VendorEnrichment should be nil when no enrichment data exists")
	}
}

func TestFetch_ListHTTPError(t *testing.T) {
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
	adapter := newTestAdapter(client)

	_, err := adapter.Fetch(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for HTTP 500 on list, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error = %q, want 'HTTP 500'", err.Error())
	}
}

func TestParseDetailResponse_ErrorPrefix(t *testing.T) {
	t.Parallel()

	_, err := parseDetailResponse(strings.NewReader(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	msg := err.Error()
	// Should NOT contain "redhat:" prefix — caller adds the prefix with CVE context
	if strings.HasPrefix(msg, "redhat:") {
		t.Errorf("parseDetailResponse should not prefix errors with 'redhat:', got: %s", msg)
	}
}

func TestFetch_LastPageAdvancesCursor(t *testing.T) {
	t.Parallel()

	// A partial page (< 100 items) signals end of pagination.
	// The adapter must still return a non-nil NextCursor with today's date
	// so the next sync starts from where we left off.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/cve.json"):
			_, _ = w.Write([]byte(`[{"CVE":"CVE-2025-0001"}]`))
		case strings.Contains(r.URL.Path, "/cve/CVE-"):
			_, _ = w.Write([]byte(`{"name":"CVE-2025-0001","details":["test"]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &redirectTransport{targetURL: ts.URL, inner: http.DefaultTransport},
	}
	adapter := newTestAdapter(client)

	cursorJSON, _ := json.Marshal(Cursor{AfterDate: "2025-01-01"})
	result, err := adapter.Fetch(context.Background(), cursorJSON)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.NextCursor == nil {
		t.Fatal("NextCursor must not be nil on last page — AfterDate must advance")
	}
	var cur Cursor
	if err := json.Unmarshal(result.NextCursor, &cur); err != nil {
		t.Fatalf("unmarshal cursor: %v", err)
	}
	if cur.AfterDate == "2025-01-01" {
		t.Error("AfterDate was not advanced from the original cursor value")
	}
	if cur.AfterDate == "" {
		t.Error("AfterDate is empty — should be today's date")
	}
	if cur.Page != 0 {
		t.Errorf("Page should be 0 (reset) on last page, got %d", cur.Page)
	}
}

// --- test helpers ---

// newTestAdapter creates an adapter with an unlimited rate limiter for fast tests.
func newTestAdapter(client *http.Client) *Adapter {
	a := New(client)
	a.rateLimiter = rate.NewLimiter(rate.Inf, 1)
	return a
}

func floatPtr(f float64) *float64 { return &f }
func strPtr(s string) *string     { return &s }
