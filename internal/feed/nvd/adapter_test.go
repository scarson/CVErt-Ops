// ABOUTME: Unit tests for the NVD feed adapter's pure parse/convert functions.
// ABOUTME: Covers cursor parsing, cursor advancement, streaming response parsing, CVE conversion, and CVSS selection.
package nvd

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
)

func TestParseCursor(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns zero value cursor", func(t *testing.T) {
		t.Parallel()
		cur, err := parseCursor(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0", cur.StartIndex)
		}
	})

	t.Run("empty input returns zero value cursor", func(t *testing.T) {
		t.Parallel()
		cur, err := parseCursor(json.RawMessage{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0", cur.StartIndex)
		}
	})

	t.Run("valid cursor JSON parsed correctly", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{
			"window_start": "2024-01-15T00:00:00Z",
			"window_end":   "2024-05-14T00:00:00Z",
			"start_index":  4000
		}`)
		cur, err := parseCursor(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantStart := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
		if !cur.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v", cur.WindowStart, wantStart)
		}
		wantEnd := time.Date(2024, 5, 14, 0, 0, 0, 0, time.UTC)
		if !cur.WindowEnd.Equal(wantEnd) {
			t.Fatalf("WindowEnd = %v, want %v", cur.WindowEnd, wantEnd)
		}
		if cur.StartIndex != 4000 {
			t.Fatalf("StartIndex = %d, want 4000", cur.StartIndex)
		}
	})

	t.Run("zero WindowStart in JSON falls back to zero value cursor", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{
			"window_start": "0001-01-01T00:00:00Z",
			"window_end":   "2024-05-14T00:00:00Z",
			"start_index":  100
		}`)
		cur, err := parseCursor(raw)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Should fall back to zero-value cursor (epoch 2002).
		if cur.WindowStart.IsZero() {
			t.Fatal("WindowStart should not be zero for zero-value cursor")
		}
		if cur.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0 (zero-value cursor resets it)", cur.StartIndex)
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		t.Parallel()
		raw := json.RawMessage(`{not valid json}`)
		_, err := parseCursor(raw)
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

func TestComputeNextCursor(t *testing.T) {
	t.Parallel()

	baseTime := time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("more pages in current window", func(t *testing.T) {
		t.Parallel()
		cur := Cursor{
			WindowStart: baseTime.Add(-48 * time.Hour),
			WindowEnd:   baseTime,
			StartIndex:  0,
		}
		next := computeNextCursor(cur, 5000, baseTime.Add(time.Hour))
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if next.StartIndex != resultsPerPage {
			t.Fatalf("StartIndex = %d, want %d", next.StartIndex, resultsPerPage)
		}
		if !next.WindowStart.Equal(cur.WindowStart) {
			t.Fatalf("WindowStart changed: got %v, want %v", next.WindowStart, cur.WindowStart)
		}
		if !next.WindowEnd.Equal(cur.WindowEnd) {
			t.Fatalf("WindowEnd changed: got %v, want %v", next.WindowEnd, cur.WindowEnd)
		}
	})

	t.Run("window exhausted next window available", func(t *testing.T) {
		t.Parallel()
		windowStart := baseTime.Add(-48 * time.Hour)
		windowEnd := baseTime
		effectiveNow := baseTime.Add(72 * time.Hour)

		cur := Cursor{
			WindowStart: windowStart,
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next := computeNextCursor(cur, 100, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if next.StartIndex != 0 {
			t.Fatalf("StartIndex = %d, want 0 for new window", next.StartIndex)
		}
		// 15-minute overlap applied.
		wantStart := windowEnd.Add(-overlapDuration)
		if !next.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v (with overlap)", next.WindowStart, wantStart)
		}
	})

	t.Run("window exhausted reached effectiveNow returns nil", func(t *testing.T) {
		t.Parallel()
		cur := Cursor{
			WindowStart: baseTime.Add(-48 * time.Hour),
			WindowEnd:   baseTime,
			StartIndex:  0,
		}
		// effectiveNow is at or before the window end — no more windows.
		next := computeNextCursor(cur, 100, baseTime)
		if next != nil {
			t.Fatalf("expected nil cursor when at effectiveNow, got %+v", next)
		}
	})

	t.Run("15 minute overlap applied to next window start", func(t *testing.T) {
		t.Parallel()
		windowEnd := baseTime
		effectiveNow := baseTime.Add(200 * 24 * time.Hour)

		cur := Cursor{
			WindowStart: baseTime.Add(-10 * 24 * time.Hour),
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next := computeNextCursor(cur, 0, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		wantStart := windowEnd.Add(-overlapDuration)
		if !next.WindowStart.Equal(wantStart) {
			t.Fatalf("WindowStart = %v, want %v (overlap)", next.WindowStart, wantStart)
		}
	})

	t.Run("next window end capped to effectiveNow", func(t *testing.T) {
		t.Parallel()
		windowEnd := baseTime
		// effectiveNow is less than windowMax from the next window start,
		// so end should be capped.
		effectiveNow := baseTime.Add(24 * time.Hour)

		cur := Cursor{
			WindowStart: baseTime.Add(-10 * 24 * time.Hour),
			WindowEnd:   windowEnd,
			StartIndex:  0,
		}
		next := computeNextCursor(cur, 0, effectiveNow)
		if next == nil {
			t.Fatal("expected non-nil next cursor")
		}
		if !next.WindowEnd.Equal(effectiveNow) {
			t.Fatalf("WindowEnd = %v, want %v (capped to effectiveNow)", next.WindowEnd, effectiveNow)
		}
	})
}

func TestParseNVDResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid response with metadata and vulnerabilities", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 2,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-0001",
						"vulnStatus": "Analyzed",
						"published": "2024-01-01T00:00:00.000",
						"lastModified": "2024-02-01T00:00:00.000",
						"descriptions": [
							{"lang": "en", "value": "A test vuln"}
						]
					}
				},
				{
					"cve": {
						"id": "CVE-2024-0002",
						"vulnStatus": "Modified",
						"published": "2024-03-01T00:00:00.000",
						"lastModified": "2024-04-01T00:00:00.000",
						"descriptions": [
							{"lang": "en", "value": "Another vuln"}
						]
					}
				}
			]
		}`
		patches, total, ts, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 2 {
			t.Fatalf("totalResults = %d, want 2", total)
		}
		if ts.IsZero() {
			t.Fatal("timestamp should not be zero")
		}
		if len(patches) != 2 {
			t.Fatalf("len(patches) = %d, want 2", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("patches[0].CVEID = %q, want CVE-2024-0001", patches[0].CVEID)
		}
		if patches[1].CVEID != "CVE-2024-0002" {
			t.Fatalf("patches[1].CVEID = %q, want CVE-2024-0002", patches[1].CVEID)
		}
	})

	t.Run("empty vulnerabilities array", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 0,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": []
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 0 {
			t.Fatalf("totalResults = %d, want 0", total)
		}
		if len(patches) != 0 {
			t.Fatalf("len(patches) = %d, want 0", len(patches))
		}
	})

	t.Run("response with only metadata no vulnerabilities key", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 42,
			"timestamp": "2024-06-01T12:00:00.000"
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 42 {
			t.Fatalf("totalResults = %d, want 42", total)
		}
		if len(patches) != 0 {
			t.Fatalf("len(patches) = %d, want 0", len(patches))
		}
	})

	t.Run("malformed individual records skipped", func(t *testing.T) {
		t.Parallel()
		body := `{
			"totalResults": 3,
			"timestamp": "2024-06-01T12:00:00.000",
			"vulnerabilities": [
				{
					"cve": {
						"id": "CVE-2024-0001",
						"vulnStatus": "Analyzed",
						"descriptions": [{"lang": "en", "value": "Good record"}]
					}
				},
				"this is not a valid json object",
				{
					"cve": {
						"id": "CVE-2024-0003",
						"vulnStatus": "Modified",
						"descriptions": [{"lang": "en", "value": "After bad record"}]
					}
				}
			]
		}`
		patches, total, _, err := parseNVDResponse(strings.NewReader(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 3 {
			t.Fatalf("totalResults = %d, want 3", total)
		}
		// The malformed string record is skipped; we get the two valid CVEs.
		if len(patches) != 2 {
			t.Fatalf("len(patches) = %d, want 2 (malformed record skipped)", len(patches))
		}
		if patches[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("patches[0].CVEID = %q, want CVE-2024-0001", patches[0].CVEID)
		}
		if patches[1].CVEID != "CVE-2024-0003" {
			t.Fatalf("patches[1].CVEID = %q, want CVE-2024-0003", patches[1].CVEID)
		}
	})
}

func TestCveToCanonical(t *testing.T) {
	t.Parallel()

	t.Run("normal record with all fields", func(t *testing.T) {
		t.Parallel()
		cve := nvdCVE{
			ID:           "CVE-2024-1234",
			VulnStatus:   "Analyzed",
			Published:    "2024-01-15T10:00:00.000",
			LastModified: "2024-02-20T14:30:00.000",
			Descriptions: []nvdDescription{
				{Lang: "en", Value: "Buffer overflow in example"},
				{Lang: "es", Value: "Desbordamiento de búfer en ejemplo"},
			},
			Weaknesses: []nvdWeakness{
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-120"},
				}},
			},
			Configurations: []nvdConfig{
				{Nodes: []nvdNode{
					{CPEMatch: []nvdCPEMatch{
						{Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", Vulnerable: true},
					}},
				}},
			},
			References: []nvdReference{
				{URL: "https://example.com/advisory", Tags: []string{"Vendor Advisory"}},
			},
			Metrics: nvdMetrics{
				CVSSV31: []nvdCVSSMetric{
					{
						Source: "nvd@nist.gov",
						CVSSData: nvdCVSSData{
							Version:      "3.1",
							VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							BaseScore:    9.8,
							BaseSeverity: "Critical",
						},
					},
				},
			},
		}

		p := cveToCanonical(cve)
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.CVEID != "CVE-2024-1234" {
			t.Fatalf("CVEID = %q, want CVE-2024-1234", p.CVEID)
		}
		if p.SourceID != "CVE-2024-1234" {
			t.Fatalf("SourceID = %q, want CVE-2024-1234", p.SourceID)
		}
		if p.Status != "Analyzed" {
			t.Fatalf("Status = %q, want Analyzed", p.Status)
		}
		if p.IsWithdrawn {
			t.Fatal("IsWithdrawn should be false for Analyzed status")
		}
		if p.DatePublished == nil {
			t.Fatal("DatePublished should not be nil")
		}
		if p.DateModified == nil {
			t.Fatal("DateModified should not be nil")
		}
		if p.DescriptionPrimary == nil || *p.DescriptionPrimary != "Buffer overflow in example" {
			t.Fatalf("DescriptionPrimary = %v, want 'Buffer overflow in example'", p.DescriptionPrimary)
		}
		if len(p.CWEIDs) != 1 || p.CWEIDs[0] != "CWE-120" {
			t.Fatalf("CWEIDs = %v, want [CWE-120]", p.CWEIDs)
		}
		if len(p.AffectedCPEs) != 1 {
			t.Fatalf("len(AffectedCPEs) = %d, want 1", len(p.AffectedCPEs))
		}
		if p.AffectedCPEs[0].CPE != "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*" {
			t.Fatalf("CPE = %q, unexpected", p.AffectedCPEs[0].CPE)
		}
		if len(p.References) != 1 || p.References[0].URL != "https://example.com/advisory" {
			t.Fatalf("References = %v, unexpected", p.References)
		}
		if p.CVSSv3Score == nil || *p.CVSSv3Score != 9.8 {
			t.Fatalf("CVSSv3Score = %v, want 9.8", p.CVSSv3Score)
		}
		if p.CVSSv3Vector == nil || *p.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
			t.Fatalf("CVSSv3Vector = %v, unexpected", p.CVSSv3Vector)
		}
		if p.Severity == nil || *p.Severity != "CRITICAL" {
			t.Fatalf("Severity = %v, want CRITICAL", p.Severity)
		}
	})

	t.Run("empty ID returns nil", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{ID: ""})
		if p != nil {
			t.Fatalf("expected nil for empty ID, got %+v", p)
		}
	})

	t.Run("rejected status sets IsWithdrawn", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID:         "CVE-2024-9999",
			VulnStatus: "Rejected",
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if !p.IsWithdrawn {
			t.Fatal("IsWithdrawn should be true for Rejected status")
		}
	})

	t.Run("english description selected non-english skipped", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5000",
			Descriptions: []nvdDescription{
				{Lang: "es", Value: "Una vulnerabilidad critica"},
				{Lang: "en", Value: "English description"},
				{Lang: "fr", Value: "Description en francais"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if p.DescriptionPrimary == nil {
			t.Fatal("DescriptionPrimary should not be nil")
		}
		if *p.DescriptionPrimary != "English description" {
			t.Fatalf("DescriptionPrimary = %q, want 'English description'", *p.DescriptionPrimary)
		}
	})

	t.Run("CWE deduplication and prefix filtering", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5001",
			Weaknesses: []nvdWeakness{
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-79"},
					{Lang: "en", Value: "NVD-CWE-Other"},
				}},
				{Description: []nvdDescription{
					{Lang: "en", Value: "CWE-79"},
					{Lang: "en", Value: "CWE-89"},
				}},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		// CWE-79 appears twice, NVD-CWE-Other should be excluded (no CWE- prefix).
		if len(p.CWEIDs) != 2 {
			t.Fatalf("len(CWEIDs) = %d, want 2, got %v", len(p.CWEIDs), p.CWEIDs)
		}
		cweSet := make(map[string]bool)
		for _, id := range p.CWEIDs {
			cweSet[id] = true
		}
		if !cweSet["CWE-79"] {
			t.Fatal("CWE-79 should be present")
		}
		if !cweSet["CWE-89"] {
			t.Fatal("CWE-89 should be present")
		}
	})

	t.Run("CPE deduplication by normalized form", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5002",
			Configurations: []nvdConfig{
				{Nodes: []nvdNode{
					{CPEMatch: []nvdCPEMatch{
						{Criteria: "cpe:2.3:a:Vendor:Product:1.0:*:*:*:*:*:*:*"},
						{Criteria: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
						{Criteria: "cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*"},
					}},
				}},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		// First two CPEs normalize to the same lowercase string, so deduplicated.
		if len(p.AffectedCPEs) != 2 {
			t.Fatalf("len(AffectedCPEs) = %d, want 2, got %v", len(p.AffectedCPEs), p.AffectedCPEs)
		}
	})

	t.Run("references with empty URL skipped", func(t *testing.T) {
		t.Parallel()
		p := cveToCanonical(nvdCVE{
			ID: "CVE-2024-5003",
			References: []nvdReference{
				{URL: "https://example.com/valid"},
				{URL: ""},
				{URL: "https://example.com/also-valid"},
			},
		})
		if p == nil {
			t.Fatal("expected non-nil patch")
		}
		if len(p.References) != 2 {
			t.Fatalf("len(References) = %d, want 2", len(p.References))
		}
		if p.References[0].URL != "https://example.com/valid" {
			t.Fatalf("References[0].URL = %q, unexpected", p.References[0].URL)
		}
		if p.References[1].URL != "https://example.com/also-valid" {
			t.Fatalf("References[1].URL = %q, unexpected", p.References[1].URL)
		}
	})
}

func TestApplyNVDCVSS(t *testing.T) {
	t.Parallel()

	t.Run("v31 preferred over v30", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 7.5, BaseSeverity: "High"},
				},
			},
			CVSSV30: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.0", VectorString: "CVSS:3.0/AV:N", BaseScore: 6.0, BaseSeverity: "Medium"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Fatalf("CVSSv3Score = %v, want 7.5 (v3.1 preferred)", patch.CVSSv3Score)
		}
		if patch.CVSSv3Vector == nil || *patch.CVSSv3Vector != "CVSS:3.1/AV:N" {
			t.Fatalf("CVSSv3Vector = %v, want CVSS:3.1/AV:N", patch.CVSSv3Vector)
		}
	})

	t.Run("v30 fallback when no v31", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV30: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.0", VectorString: "CVSS:3.0/AV:L", BaseScore: 5.5, BaseSeverity: "Medium"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 5.5 {
			t.Fatalf("CVSSv3Score = %v, want 5.5 (v3.0 fallback)", patch.CVSSv3Score)
		}
	})

	t.Run("v40 set independently", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 9.8, BaseSeverity: "Critical"},
				},
			},
			CVSSV40: []nvdCVSSMetric{
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "4.0", VectorString: "CVSS:4.0/AV:N", BaseScore: 8.7, BaseSeverity: "High"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 9.8 {
			t.Fatalf("CVSSv3Score = %v, want 9.8", patch.CVSSv3Score)
		}
		if patch.CVSSv4Score == nil || *patch.CVSSv4Score != 8.7 {
			t.Fatalf("CVSSv4Score = %v, want 8.7", patch.CVSSv4Score)
		}
		if patch.CVSSv4Vector == nil || *patch.CVSSv4Vector != "CVSS:4.0/AV:N" {
			t.Fatalf("CVSSv4Vector = %v, want CVSS:4.0/AV:N", patch.CVSSv4Vector)
		}
		// Severity comes from v3.1 (set first), not overridden by v4.0.
		if patch.Severity == nil || *patch.Severity != "CRITICAL" {
			t.Fatalf("Severity = %v, want CRITICAL (from v3.1, not overridden by v4.0)", patch.Severity)
		}
	})

	t.Run("nvd source preferred via pickPreferred", func(t *testing.T) {
		t.Parallel()
		patch := &feed.CanonicalPatch{}
		m := nvdMetrics{
			CVSSV31: []nvdCVSSMetric{
				{
					Source:   "vendor@example.com",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:L", BaseScore: 4.0, BaseSeverity: "Medium"},
				},
				{
					Source:   "nvd@nist.gov",
					CVSSData: nvdCVSSData{Version: "3.1", VectorString: "CVSS:3.1/AV:N", BaseScore: 7.5, BaseSeverity: "High"},
				},
			},
		}
		applyNVDCVSS(patch, m)
		if patch.CVSSv3Score == nil || *patch.CVSSv3Score != 7.5 {
			t.Fatalf("CVSSv3Score = %v, want 7.5 (NVD source preferred)", patch.CVSSv3Score)
		}
	})
}

func TestPickPreferred(t *testing.T) {
	t.Parallel()

	t.Run("nvd source entry returned when present", func(t *testing.T) {
		t.Parallel()
		entries := []nvdCVSSMetric{
			{Source: "vendor@example.com", CVSSData: nvdCVSSData{BaseScore: 4.0}},
			{Source: "nvd@nist.gov", CVSSData: nvdCVSSData{BaseScore: 7.5}},
			{Source: "other@example.com", CVSSData: nvdCVSSData{BaseScore: 5.0}},
		}
		got := pickPreferred(entries)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got.Source != "nvd@nist.gov" {
			t.Fatalf("Source = %q, want nvd@nist.gov", got.Source)
		}
		if got.CVSSData.BaseScore != 7.5 {
			t.Fatalf("BaseScore = %v, want 7.5", got.CVSSData.BaseScore)
		}
	})

	t.Run("first entry returned when no nvd source", func(t *testing.T) {
		t.Parallel()
		entries := []nvdCVSSMetric{
			{Source: "vendor@example.com", CVSSData: nvdCVSSData{BaseScore: 4.0}},
			{Source: "other@example.com", CVSSData: nvdCVSSData{BaseScore: 5.0}},
		}
		got := pickPreferred(entries)
		if got == nil {
			t.Fatal("expected non-nil result")
		}
		if got.Source != "vendor@example.com" {
			t.Fatalf("Source = %q, want vendor@example.com (first entry)", got.Source)
		}
	})

	t.Run("empty slice returns nil", func(t *testing.T) {
		t.Parallel()
		got := pickPreferred(nil)
		if got != nil {
			t.Fatalf("expected nil for empty slice, got %+v", got)
		}
		got = pickPreferred([]nvdCVSSMetric{})
		if got != nil {
			t.Fatalf("expected nil for zero-length slice, got %+v", got)
		}
	})
}
