// ABOUTME: Tests for template rendering of alert, digest, and invitation emails.
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

// TestRenderAlert_XSSEscaping verifies that adversarial input containing HTML/JS
// is auto-escaped by html/template, preventing XSS in rendered email output.
func TestRenderAlert_XSSEscaping(t *testing.T) {
	xssPayload := `<script>alert('xss')</script>`
	data := AlertTemplateData{
		RuleName: xssPayload,
		RuleID:   "rule-xss",
		CVEs: []CVESummary{
			{
				CVEID:       "CVE-2024-XSS",
				Severity:    xssPayload,
				Description: xssPayload,
			},
		},
		CVErtOpsURL: "https://app.example.com",
	}

	_, html, _, err := RenderAlert(data)
	if err != nil {
		t.Fatalf("RenderAlert: %v", err)
	}

	// The HTML output must NOT contain the raw script tag.
	if strings.Contains(html, "<script>") {
		t.Error("HTML output contains unescaped <script> tag — XSS vulnerability")
	}
	// html/template escapes < as &lt;
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("HTML output should contain escaped form of <script>")
	}
}

// TestRenderDigest_XSSEscaping verifies XSS escaping in digest email templates.
func TestRenderDigest_XSSEscaping(t *testing.T) {
	xssPayload := `<img src=x onerror=alert(1)>`
	data := DigestTemplateData{
		OrgName:    xssPayload,
		ReportName: xssPayload,
		Date:       "2026-03-01",
		CVEs: []CVESummary{
			{
				CVEID:       "CVE-2024-XSS2",
				Severity:    "critical",
				Description: xssPayload,
			},
		},
		TotalCount:  1,
		CVErtOpsURL: "https://app.example.com",
	}

	_, html, _, err := RenderDigest(data)
	if err != nil {
		t.Fatalf("RenderDigest: %v", err)
	}

	if strings.Contains(html, "<img src=x") {
		t.Error("HTML output contains unescaped <img> tag — XSS vulnerability")
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

func TestSnapshotsToCVESummaries_EdgeCases(t *testing.T) {
	t.Run("nil severity", func(t *testing.T) {
		snaps := []cveSnapshot{{CVEID: "CVE-2024-NIL", Severity: nil}}
		out := snapshotsToCVESummaries(snaps, "https://app.example.com")
		if out[0].Severity != "" {
			t.Errorf("nil severity should produce empty string, got %q", out[0].Severity)
		}
	})

	t.Run("empty baseURL", func(t *testing.T) {
		snaps := []cveSnapshot{{CVEID: "CVE-2024-NOURL"}}
		out := snapshotsToCVESummaries(snaps, "")
		if out[0].DetailURL != "" {
			t.Errorf("empty baseURL should produce empty DetailURL, got %q", out[0].DetailURL)
		}
	})

	t.Run("short description not truncated", func(t *testing.T) {
		desc := "Short description under 280 chars."
		snaps := []cveSnapshot{{CVEID: "CVE-2024-SHORT", Description: desc}}
		out := snapshotsToCVESummaries(snaps, "")
		if out[0].Description != desc {
			t.Errorf("short description should pass through unchanged, got %q", out[0].Description)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		out := snapshotsToCVESummaries(nil, "https://app.example.com")
		if len(out) != 0 {
			t.Errorf("nil input should produce empty output, got %d items", len(out))
		}
	})

	t.Run("all score fields populated", func(t *testing.T) {
		snaps := []cveSnapshot{{
			CVEID:       "CVE-2024-SCORES",
			CVSSV3Score: ptr(8.5),
			CVSSV4Score: ptr(7.2),
			EPSSScore:   ptr(0.95),
			InCISAKEV:   true,
		}}
		out := snapshotsToCVESummaries(snaps, "")
		s := out[0]
		if s.CVSSV3Score == nil || *s.CVSSV3Score != 8.5 {
			t.Error("CVSSV3Score not passed through")
		}
		if s.CVSSV4Score == nil || *s.CVSSV4Score != 7.2 {
			t.Error("CVSSV4Score not passed through")
		}
		if s.EPSSScore == nil || *s.EPSSScore != 0.95 {
			t.Error("EPSSScore not passed through")
		}
		if !s.InCISAKEV {
			t.Error("InCISAKEV not passed through")
		}
	})
}

func TestRenderInvitation_BasicOutput(t *testing.T) {
	data := InvitationData{
		OrgName:     "Acme Corp",
		InviterName: "Alice",
		Role:        "admin",
		InviteURL:   "https://app.example.com/invitations/abc123",
		ExpiresAt:   "January 15, 2026",
	}
	subject, html, text, err := RenderInvitation(data)
	if err != nil {
		t.Fatalf("RenderInvitation: %v", err)
	}
	if !strings.Contains(subject, "Acme Corp") {
		t.Errorf("subject missing org name: %q", subject)
	}
	if !strings.Contains(html, "Alice") {
		t.Error("HTML body missing inviter name")
	}
	if !strings.Contains(html, "admin") {
		t.Error("HTML body missing role")
	}
	if !strings.Contains(html, "https://app.example.com/invitations/abc123") {
		t.Error("HTML body missing invite URL")
	}
	if !strings.Contains(text, "Alice") {
		t.Error("text body missing inviter name")
	}
	if !strings.Contains(text, "https://app.example.com/invitations/abc123") {
		t.Error("text body missing invite URL")
	}
}

// ── MFA OTP Email Rendering (P11 Task 7 SC9) ───────────────────────────────

func TestRenderMFAOTP_BasicOutput(t *testing.T) {
	subject, html, text, err := RenderMFAOTP(MFAOTPData{Code: "123456", ExpiresIn: "10 minutes"})
	if err != nil {
		t.Fatalf("RenderMFAOTP: %v", err)
	}
	if subject == "" {
		t.Error("subject is empty")
	}
	if html == "" {
		t.Error("HTML body is empty")
	}
	if text == "" {
		t.Error("text body is empty")
	}
	if !strings.Contains(html, "123456") {
		t.Error("HTML body missing code")
	}
	if !strings.Contains(html, "10 minutes") {
		t.Error("HTML body missing expiry")
	}
	if !strings.Contains(text, "123456") {
		t.Error("text body missing code")
	}
	if !strings.Contains(text, "10 minutes") {
		t.Error("text body missing expiry")
	}
}

func TestRenderMFAOTP_SubjectSanitization(t *testing.T) {
	subject, _, _, err := RenderMFAOTP(MFAOTPData{Code: "654321", ExpiresIn: "5 minutes"})
	if err != nil {
		t.Fatalf("RenderMFAOTP: %v", err)
	}
	if strings.Contains(subject, "\r") || strings.Contains(subject, "\n") {
		t.Errorf("subject contains CRLF (header injection risk): %q", subject)
	}
}
