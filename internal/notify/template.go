// ABOUTME: Template data structs for alert and digest email rendering.
// ABOUTME: CVESummary is converted from cveSnapshot at render time with nil-safe accessors.
package notify

// CVESummary is the template-ready representation of a CVE for email rendering.
type CVESummary struct {
	CVEID        string
	Severity     string
	CVSSV3Score  *float64
	CVSSV4Score  *float64
	EPSSScore    *float64
	Description  string
	ExploitAvail bool
	InCISAKEV    bool
	DetailURL    string
}

// AlertTemplateData is the context passed to alert email templates.
type AlertTemplateData struct {
	RuleName    string
	RuleID      string
	CVEs        []CVESummary
	CVErtOpsURL string
}

// DigestTemplateData is the context passed to digest email templates.
type DigestTemplateData struct {
	OrgName     string
	ReportName  string
	Date        string
	CVEs        []CVESummary
	TotalCount  int
	Truncated   bool
	ViewAllURL  string
	AISummary   string
	CVErtOpsURL string
}

// snapshotsToCVESummaries converts delivery payload snapshots to template-ready summaries.
// Truncates descriptions to 280 chars and constructs detail URLs.
func snapshotsToCVESummaries(snaps []cveSnapshot, baseURL string) []CVESummary {
	out := make([]CVESummary, len(snaps))
	for i, s := range snaps {
		sev := ""
		if s.Severity != nil {
			sev = *s.Severity
		}
		desc := s.Description
		if len(desc) > 280 {
			desc = desc[:277] + "..."
		}
		var detailURL string
		if baseURL != "" {
			detailURL = baseURL + "/cves/" + s.CVEID
		}
		out[i] = CVESummary{
			CVEID:        s.CVEID,
			Severity:     sev,
			CVSSV3Score:  s.CVSSV3Score,
			CVSSV4Score:  s.CVSSV4Score,
			EPSSScore:    s.EPSSScore,
			Description:  desc,
			ExploitAvail: s.ExploitAvail,
			InCISAKEV:    s.InCISAKEV,
			DetailURL:    detailURL,
		}
	}
	return out
}
