// ABOUTME: Tests the advisory fields that come from outside its verdict: cve_ids, KEV and EPSS, and list order.
// ABOUTME: Covers design section 6 (cve_ids, exploit data from the CVE rows) and section 9's listing order.
package check

import (
	"reflect"
	"testing"
)

func TestCVEIDsFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id   string
		want []string
	}{
		{"CVE-2026-111497", []string{"CVE-2026-111497"}},
		{"UBUNTU-CVE-2026-109618", []string{"CVE-2026-109618"}},
		{"DEBIAN-CVE-2024-7347", []string{"CVE-2024-7347"}},
		{"ALPINE-CVE-2021-44228", []string{"CVE-2021-44228"}},
		{"USN-8948-1", []string{}},
		{"DSA-5800-1", []string{}},
		{"GHSA-xxxx-yyyy-zzzz", []string{}},
		{"UBUNTU-2026-1", []string{}},
		{"", []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			t.Parallel()
			got := CVEIDsFor(tt.id)
			if got == nil {
				t.Fatal("CVEIDsFor returned nil; want a non-nil slice so the JSON is []")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CVEIDsFor(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestExploitData checks design section 6: KEV is true if any of the CVEs is,
// EPSS is the highest, and both are null when no CVE can be read.
func TestExploitData(t *testing.T) {
	t.Parallel()
	enrichment := map[string]CVEEnrichment{
		"CVE-A": {InCISAKEV: true, EPSSScore: ptr(0.2)},
		"CVE-B": {InCISAKEV: false, EPSSScore: ptr(0.7)},
		"CVE-C": {InCISAKEV: false},
	}
	tests := []struct {
		name     string
		cveIDs   []string
		wantKEV  *bool
		wantEPSS *float64
	}{
		{"no CVEs gives null for both", []string{}, nil, nil},
		{"CVEs with no enrichment give null for both", []string{"CVE-X", "CVE-Y"}, nil, nil},
		{"KEV true if any CVE is in KEV", []string{"CVE-B", "CVE-A"}, ptr(true), ptr(0.7)},
		{"KEV false when every known CVE is false", []string{"CVE-B", "CVE-C", "CVE-X"}, ptr(false), ptr(0.7)},
		{"EPSS null when no CVE has a score", []string{"CVE-C"}, ptr(false), nil},
		{"EPSS is the highest score", []string{"CVE-A", "CVE-C", "CVE-B"}, ptr(true), ptr(0.7)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			kev, epss := exploitData(tt.cveIDs, enrichment)
			if !reflect.DeepEqual(kev, tt.wantKEV) {
				t.Errorf("in_cisa_kev = %v, want %v", deref(kev), deref(tt.wantKEV))
			}
			if !reflect.DeepEqual(epss, tt.wantEPSS) {
				t.Errorf("epss_score = %v, want %v", deref(epss), deref(tt.wantEPSS))
			}
		})
	}
}

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

// TestSortAdvisories checks the listing order of design section 9: Affected
// first, then KEV true, then CVSS v3 score and EPSS score descending with null
// last, then advisory_id ascending.
func TestSortAdvisories(t *testing.T) {
	t.Parallel()
	advisories := []Advisory{
		{AdvisoryID: "Z-cannot", Verdict: VerdictCannotEvaluate, InCISAKEV: ptr(true), CVSSv3Score: ptr(10.0)},
		{AdvisoryID: "B-null-scores", Verdict: VerdictAffected},
		{AdvisoryID: "A-null-scores", Verdict: VerdictAffected},
		{AdvisoryID: "C-epss-high", Verdict: VerdictAffected, CVSSv3Score: ptr(5.0), EPSSScore: ptr(0.9)},
		{AdvisoryID: "D-epss-low", Verdict: VerdictAffected, CVSSv3Score: ptr(5.0), EPSSScore: ptr(0.1)},
		{AdvisoryID: "E-epss-null", Verdict: VerdictAffected, CVSSv3Score: ptr(5.0)},
		{AdvisoryID: "F-cvss-high", Verdict: VerdictAffected, CVSSv3Score: ptr(9.8)},
		{AdvisoryID: "G-kev-false", Verdict: VerdictAffected, InCISAKEV: ptr(false), CVSSv3Score: ptr(9.9)},
		{AdvisoryID: "H-kev", Verdict: VerdictAffected, InCISAKEV: ptr(true), CVSSv3Score: ptr(1.0)},
		{AdvisoryID: "Y-cannot", Verdict: VerdictCannotEvaluate},
	}
	sortAdvisories(advisories)
	var got []string
	for _, a := range advisories {
		got = append(got, a.AdvisoryID)
	}
	want := []string{
		"H-kev", "G-kev-false", "F-cvss-high", "C-epss-high", "D-epss-low", "E-epss-null",
		"A-null-scores", "B-null-scores", "Z-cannot", "Y-cannot",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("order = %v\nwant    %v", got, want)
	}
}
