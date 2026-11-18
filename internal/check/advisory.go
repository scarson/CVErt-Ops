// ABOUTME: Advisory fields that do not come from its verdict: cve_ids, KEV and EPSS from the CVE rows, and list order.
// ABOUTME: Design section 6 (distro records, exploit data) and section 9 (listing order).
package check

import (
	"cmp"
	"slices"
	"strings"
)

// CVEEnrichment is one cves row's severity and exploit data, keyed by cve_id.
type CVEEnrichment struct {
	Severity    *string
	CVSSv3Score *float64
	InCISAKEV   bool
	EPSSScore   *float64
}

// distroCVEPrefixes are the distro record prefixes whose ID names exactly one
// CVE, as UBUNTU-CVE-2026-109618 names CVE-2026-109618.
var distroCVEPrefixes = []string{"UBUNTU-", "DEBIAN-", "ALPINE-"}

// CVEIDsFor returns the CVEs an advisory record covers: a CVE record itself, the
// CVE a per-CVE distro record names, and none for any other record (USN-*, DSA-*,
// GHSA-*), whose CVEs the corpus does not link. The slice is never nil.
func CVEIDsFor(advisoryID string) []string {
	if strings.HasPrefix(advisoryID, "CVE-") {
		return []string{advisoryID}
	}
	for _, prefix := range distroCVEPrefixes {
		if cve, ok := strings.CutPrefix(advisoryID, prefix); ok && strings.HasPrefix(cve, "CVE-") {
			return []string{cve}
		}
	}
	return []string{}
}

// exploitData returns in_cisa_kev and epss_score for an advisory from its CVEs'
// rows: KEV true if any CVE is in KEV, EPSS the highest score. Each is null when
// no CVE row gives a value, which means "not known", never false.
func exploitData(cveIDs []string, enrichment map[string]CVEEnrichment) (kev *bool, epss *float64) {
	for _, id := range cveIDs {
		e, ok := enrichment[id]
		if !ok {
			continue
		}
		if kev == nil {
			kev = new(bool)
		}
		*kev = *kev || e.InCISAKEV
		if e.EPSSScore != nil && (epss == nil || *e.EPSSScore > *epss) {
			epss = e.EPSSScore
		}
	}
	return kev, epss
}

// sortAdvisories orders listed advisories: Affected first, then those in KEV,
// then by CVSS v3 score and by EPSS score, each highest first with null last,
// then by advisory_id.
func sortAdvisories(advisories []Advisory) {
	slices.SortFunc(advisories, func(a, b Advisory) int {
		return cmp.Or(
			descending(a.Verdict == VerdictAffected, b.Verdict == VerdictAffected),
			descending(a.InCISAKEV != nil && *a.InCISAKEV, b.InCISAKEV != nil && *b.InCISAKEV),
			descendingScore(a.CVSSv3Score, b.CVSSv3Score),
			descendingScore(a.EPSSScore, b.EPSSScore),
			strings.Compare(a.AdvisoryID, b.AdvisoryID),
		)
	})
}

// descending orders true before false.
func descending(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return -1
	default:
		return 1
	}
}

// descendingScore orders the higher score first and a null score last.
func descendingScore(a, b *float64) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	default:
		return cmp.Compare(*b, *a)
	}
}
