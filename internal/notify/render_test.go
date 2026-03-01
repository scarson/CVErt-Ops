// ABOUTME: Tests for template rendering of alert and digest emails.
// ABOUTME: Verifies subject lines, HTML/text output, truncation, heartbeat, AI summary.
package notify

import (
	"strings"
	"testing"
)

func ptr(v float64) *float64 { return &v }

func TestRenderAlert_BasicOutput(t *testing.T) {
	data := AlertTemplateData{
		RuleName: "Critical Vulns",
		RuleID:   "rule-123",
		CVEs: []CVESummary{
			{
				CVEID:        "CVE-2024-1234",
				Severity:     "critical",
				CVSSV3Score:  ptr(9.8),
				Description:  "A critical vulnerability in example software.",
				ExploitAvail: true,
				InCISAKEV:    true,
				DetailURL:    "https://app.example.com/cves/CVE-2024-1234",
			},
			{
				CVEID:       "CVE-2024-5678",
				Severity:    "high",
				CVSSV3Score: ptr(7.5),
				EPSSScore:   ptr(0.45),
				Description: "Another vulnerability.",
			},
		},
		CVErtOpsURL: "https://app.example.com",
	}

	subject, html, text, err := RenderAlert(data)
	if err != nil {
		t.Fatalf("RenderAlert: %v", err)
	}

	if !strings.Contains(subject, "Critical Vulns") {
		t.Errorf("subject missing rule name: %q", subject)
	}
	if !strings.Contains(subject, "2 CVE(s)") {
		t.Errorf("subject missing CVE count: %q", subject)
	}
	if !strings.Contains(html, "CVE-2024-1234") {
		t.Error("HTML missing CVE ID")
	}
	if !strings.Contains(html, "CVE-2024-5678") {
		t.Error("HTML missing second CVE ID")
	}
	if !strings.Contains(text, "CVE-2024-1234") {
		t.Error("text missing CVE ID")
	}
	if !strings.Contains(text, "EXPLOIT AVAILABLE") {
		t.Error("text missing exploit flag")
	}
	if !strings.Contains(text, "CISA KEV") {
		t.Error("text missing KEV flag")
	}
}

func TestRenderAlert_EmptyCVEs(t *testing.T) {
	data := AlertTemplateData{
		RuleName: "Empty Rule",
		RuleID:   "rule-000",
		CVEs:     nil,
	}
	subject, _, _, err := RenderAlert(data)
	if err != nil {
		t.Fatalf("RenderAlert (empty): %v", err)
	}
	if !strings.Contains(subject, "0 CVE(s)") {
		t.Errorf("subject should show 0 CVEs: %q", subject)
	}
}

func TestRenderDigest_TruncationFooter(t *testing.T) {
	data := DigestTemplateData{
		OrgName:    "Acme Corp",
		ReportName: "Daily Digest",
		Date:       "2026-02-28",
		CVEs: []CVESummary{
			{CVEID: "CVE-2024-0001", Severity: "medium"},
		},
		TotalCount:  50,
		Truncated:   true,
		ViewAllURL:  "https://app.example.com/reports/1",
		CVErtOpsURL: "https://app.example.com",
	}

	_, html, text, err := RenderDigest(data)
	if err != nil {
		t.Fatalf("RenderDigest: %v", err)
	}

	if !strings.Contains(html, "1 of 50") {
		t.Error("HTML missing truncation footer")
	}
	if !strings.Contains(text, "1 of 50") {
		t.Error("text missing truncation count")
	}
}

func TestRenderDigest_Heartbeat(t *testing.T) {
	data := DigestTemplateData{
		OrgName:    "Acme Corp",
		ReportName: "Daily Digest",
		Date:       "2026-02-28",
		CVEs:       nil,
		TotalCount: 0,
	}

	_, html, text, err := RenderDigest(data)
	if err != nil {
		t.Fatalf("RenderDigest (heartbeat): %v", err)
	}

	if !strings.Contains(html, "No new CVEs") {
		t.Error("HTML missing heartbeat message")
	}
	if !strings.Contains(text, "No new CVEs") {
		t.Error("text missing heartbeat message")
	}
}

func TestRenderDigest_AISummaryPlumbing(t *testing.T) {
	data := DigestTemplateData{
		OrgName:    "Acme Corp",
		ReportName: "AI Digest",
		Date:       "2026-02-28",
		CVEs:       []CVESummary{{CVEID: "CVE-2024-0001", Severity: "high"}},
		TotalCount: 1,
		AISummary:  "Two critical vulnerabilities require immediate patching.",
	}

	_, html, text, err := RenderDigest(data)
	if err != nil {
		t.Fatalf("RenderDigest (AI summary): %v", err)
	}

	if !strings.Contains(html, "Two critical vulnerabilities") {
		t.Error("HTML missing AI summary")
	}
	if !strings.Contains(text, "Two critical vulnerabilities") {
		t.Error("text missing AI summary")
	}
}

func TestSanitizeSubject(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"Normal Subject", "Normal Subject"},
		{"With\r\nInjection", "WithInjection"},
		{"  Padded  ", "Padded"},
		{"\nLeading newline", "Leading newline"},
	}
	for _, tc := range cases {
		got := sanitizeSubject(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeSubject(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSnapshotsToCVESummaries(t *testing.T) {
	sev := "critical"
	snaps := []cveSnapshot{
		{
			CVEID:        "CVE-2024-1111",
			Severity:     &sev,
			CVSSV3Score:  ptr(9.8),
			Description:  strings.Repeat("x", 300),
			ExploitAvail: true,
		},
	}
	summaries := snapshotsToCVESummaries(snaps, "https://app.example.com")
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.CVEID != "CVE-2024-1111" {
		t.Errorf("CVEID = %q", s.CVEID)
	}
	if s.Severity != "critical" {
		t.Errorf("Severity = %q", s.Severity)
	}
	if len(s.Description) != 280 {
		t.Errorf("Description length = %d, want 280 (truncated)", len(s.Description))
	}
	if !strings.HasSuffix(s.Description, "...") {
		t.Error("truncated description should end with ...")
	}
	if s.DetailURL != "https://app.example.com/cves/CVE-2024-1111" {
		t.Errorf("DetailURL = %q", s.DetailURL)
	}
}
