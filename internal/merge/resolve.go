package merge

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/feed"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// Source name constants match the source_name values written by each feed
// adapter into cve_sources. They are exported so adapters can reference them
// when composing CanonicalPatch values.
const (
	SourceMITRE = "mitre"
	SourceNVD   = "nvd"
	SourceOSV   = "osv"
	SourceGHSA  = "ghsa"
	SourceKEV   = "kev"
	SourceEPSS  = "epss"
)

// Priority lists per field group (PLAN.md §5.1). Elements are ordered
// highest-precedence first.
var (
	// statusPriority governs: Status, IsWithdrawn, and Description.
	statusPriority = []string{SourceMITRE, SourceNVD, SourceOSV, SourceGHSA}

	// cvssPriority governs: CVSS v3/v4 scores + vectors, and Severity.
	cvssPriority = []string{SourceNVD, SourceOSV, SourceGHSA, SourceMITRE}

	// pkgPriority governs: affected package version ranges.
	pkgPriority = []string{SourceOSV, SourceGHSA, SourceNVD, SourceMITRE}
)

// ResolvedReference is a reference URL with a pre-computed canonical form
// for storage in cve_references.url_canonical.
type ResolvedReference struct {
	URL          string
	URLCanonical string
	Tags         []string
}

// ResolvedCVE is the output of the merge resolver: a single canonical CVE
// record assembled from all source patches using per-field source precedence
// rules (PLAN.md §5.1 + §5.2).
type ResolvedCVE struct {
	// Scalar fields mapped to the cves table.
	Status               string
	DatePublished        *time.Time
	DateModifiedSourceMax *time.Time // max source_date_modified across all sources
	DescriptionPrimary   *string
	Severity             string
	CVSSv3Score          *float64
	CVSSv3Vector         string
	CVSSv3Source         string // source_name that provided the winning v3 CVSS
	CVSSv4Score          *float64
	CVSSv4Vector         string
	CVSSv4Source         string // source_name that provided the winning v4 CVSS
	CVSSScoreDiverges    bool
	CWEIDs               []string // sorted, deduped union across all sources
	ExploitAvailable     bool
	InCISAKEV            bool
	IsWithdrawn          bool

	// Child table data.
	References       []ResolvedReference
	AffectedPackages []feed.AffectedPackage
	AffectedCPEs     []feed.AffectedCPE
}

// resolve builds a ResolvedCVE from the given cve_sources rows by applying
// per-field source precedence (PLAN.md §5.1). Sources not in the named
// priority lists contribute to union fields (CWEs, references, packages, CPEs)
// but never win scalar precedence over the named sources.
func resolve(sources []generated.CveSource) (ResolvedCVE, error) {
	patches := make(map[string]feed.CanonicalPatch, len(sources))
	var latestModified *time.Time

	for _, src := range sources {
		var p feed.CanonicalPatch
		if err := json.Unmarshal(src.NormalizedJson, &p); err != nil {
			// Malformed normalized_json: skip this source. The merge continues
			// with remaining well-formed sources rather than failing the whole CVE.
			continue
		}
		patches[src.SourceName] = p
		if src.SourceDateModified.Valid {
			t := src.SourceDateModified.Time
			if latestModified == nil || t.After(*latestModified) {
				tCopy := t
				latestModified = &tCopy
			}
		}
	}

	var r ResolvedCVE
	r.DateModifiedSourceMax = latestModified

	// --- Status (MITRE > NVD > OSV > GHSA, then unknown sources) ---
	r.Status = firstStr(patches, func(p feed.CanonicalPatch) string { return p.Status }, statusPriority)

	// --- IsWithdrawn: follows the same source as Status when possible,
	//     but also set if ANY source explicitly marks withdrawal. ---
	for _, src := range statusPriority {
		if p, ok := patches[src]; ok && p.Status != "" {
			r.IsWithdrawn = p.IsWithdrawn
			break
		}
	}
	if !r.IsWithdrawn {
		for _, p := range patches {
			if p.IsWithdrawn {
				r.IsWithdrawn = true
				break
			}
		}
	}

	// --- Description (MITRE > NVD > OSV > GHSA, then unknown sources) ---
	r.DescriptionPrimary = firstStrPtr(patches, func(p feed.CanonicalPatch) *string { return p.DescriptionPrimary }, statusPriority)

	// --- DatePublished: earliest non-nil across all sources ---
	for _, p := range patches {
		if p.DatePublished != nil {
			if r.DatePublished == nil || p.DatePublished.Before(*r.DatePublished) {
				tCopy := *p.DatePublished
				r.DatePublished = &tCopy
			}
		}
	}

	// --- CVSS v3 (NVD > OSV > GHSA > MITRE, then unknown sources) ---
	for _, src := range append(cvssPriority, otherSources(patches, cvssPriority)...) {
		p, ok := patches[src]
		if !ok || p.CVSSv3Score == nil {
			continue
		}
		r.CVSSv3Score = p.CVSSv3Score
		r.CVSSv3Source = src
		if p.CVSSv3Vector != nil {
			r.CVSSv3Vector = *p.CVSSv3Vector
		}
		break
	}

	// --- CVSS v4 (same priority as v3) ---
	for _, src := range append(cvssPriority, otherSources(patches, cvssPriority)...) {
		p, ok := patches[src]
		if !ok || p.CVSSv4Score == nil {
			continue
		}
		r.CVSSv4Score = p.CVSSv4Score
		r.CVSSv4Source = src
		if p.CVSSv4Vector != nil {
			r.CVSSv4Vector = *p.CVSSv4Vector
		}
		break
	}

	// --- Severity (CVSS priority first, then status priority as fallback) ---
	r.Severity = firstStr(patches, func(p feed.CanonicalPatch) string {
		if p.Severity != nil {
			return *p.Severity
		}
		return ""
	}, cvssPriority)
	if r.Severity == "" {
		r.Severity = firstStr(patches, func(p feed.CanonicalPatch) string {
			if p.Severity != nil {
				return *p.Severity
			}
			return ""
		}, statusPriority)
	}

	// --- cvss_score_diverges ---
	r.CVSSScoreDiverges = computeScoreDiverges(patches)

	// --- CISA KEV: any source asserting in_cisa_kev wins ---
	for _, p := range patches {
		if p.InCISAKEV != nil && *p.InCISAKEV {
			r.InCISAKEV = true
			break
		}
	}

	// --- Exploit available: any source asserting it wins ---
	for _, p := range patches {
		if p.ExploitAvailable != nil && *p.ExploitAvailable {
			r.ExploitAvailable = true
			break
		}
	}

	// --- CWE IDs: sorted, deduped union across all sources ---
	cweSet := make(map[string]struct{})
	for _, p := range patches {
		for _, id := range p.CWEIDs {
			if id != "" {
				cweSet[id] = struct{}{}
			}
		}
	}
	r.CWEIDs = make([]string, 0, len(cweSet))
	for id := range cweSet {
		r.CWEIDs = append(r.CWEIDs, id)
	}
	sort.Strings(r.CWEIDs)

	// --- References: union, deduped by url_canonical ---
	refSeen := make(map[string]struct{})
	for _, p := range patches {
		for _, ref := range p.References {
			canon := canonicalizeURL(ref.URL)
			if _, seen := refSeen[canon]; seen {
				continue
			}
			refSeen[canon] = struct{}{}
			r.References = append(r.References, ResolvedReference{
				URL:          ref.URL,
				URLCanonical: canon,
				Tags:         ref.Tags,
			})
		}
	}

	// --- Affected packages: union, deduped by (ecosystem, package_name, introduced),
	//     iterated in pkgPriority order so higher-precedence source wins collisions ---
	pkgSeen := make(map[string]struct{})
	for _, src := range append(pkgPriority, otherSources(patches, pkgPriority)...) {
		p, ok := patches[src]
		if !ok {
			continue
		}
		for _, pkg := range p.AffectedPackages {
			// NUL byte separator: safe because ecosystem/package names never contain NUL.
			key := pkg.Ecosystem + "\x00" + pkg.PackageName + "\x00" + pkg.Introduced
			if _, seen := pkgSeen[key]; seen {
				continue
			}
			pkgSeen[key] = struct{}{}
			r.AffectedPackages = append(r.AffectedPackages, pkg)
		}
	}

	// --- Affected CPEs: union, deduped by cpe_normalized ---
	cpeSeen := make(map[string]struct{})
	for _, p := range patches {
		for _, cpe := range p.AffectedCPEs {
			norm := cpe.CPENormalized
			if norm == "" {
				norm = strings.ToLower(cpe.CPE)
			}
			if _, seen := cpeSeen[norm]; seen {
				continue
			}
			cpeSeen[norm] = struct{}{}
			r.AffectedCPEs = append(r.AffectedCPEs, feed.AffectedCPE{
				CPE:           cpe.CPE,
				CPENormalized: norm,
			})
		}
	}

	return r, nil
}

// firstStr returns the first non-empty string produced by field() when
// iterating patches in priority order, then falling back to any source
// not in priority.
func firstStr(patches map[string]feed.CanonicalPatch, field func(feed.CanonicalPatch) string, priority []string) string {
	for _, src := range priority {
		if p, ok := patches[src]; ok {
			if v := field(p); v != "" {
				return v
			}
		}
	}
	for _, src := range otherSources(patches, priority) {
		if p, ok := patches[src]; ok {
			if v := field(p); v != "" {
				return v
			}
		}
	}
	return ""
}

// firstStrPtr returns the first non-nil *string produced by field() when
// iterating patches in priority order, then falling back to other sources.
func firstStrPtr(patches map[string]feed.CanonicalPatch, field func(feed.CanonicalPatch) *string, priority []string) *string {
	for _, src := range priority {
		if p, ok := patches[src]; ok {
			if v := field(p); v != nil {
				return v
			}
		}
	}
	for _, src := range otherSources(patches, priority) {
		if p, ok := patches[src]; ok {
			if v := field(p); v != nil {
				return v
			}
		}
	}
	return nil
}

// otherSources returns source names present in patches but not in priority.
// Results are sorted for deterministic iteration order.
func otherSources(patches map[string]feed.CanonicalPatch, priority []string) []string {
	known := make(map[string]struct{}, len(priority))
	for _, s := range priority {
		known[s] = struct{}{}
	}
	var others []string
	for s := range patches {
		if _, ok := known[s]; !ok {
			others = append(others, s)
		}
	}
	sort.Strings(others)
	return others
}

// computeScoreDiverges returns true when CVSSv3 scores from different sources
// differ by 2.0 or more (PLAN.md §5.1 cvss_score_diverges definition).
func computeScoreDiverges(patches map[string]feed.CanonicalPatch) bool {
	var min, max float64
	first := true
	for _, p := range patches {
		if p.CVSSv3Score == nil {
			continue
		}
		s := *p.CVSSv3Score
		if first {
			min, max, first = s, s, false
		} else {
			if s < min {
				min = s
			}
			if s > max {
				max = s
			}
		}
	}
	return max-min >= 2.0
}

// canonicalizeURL normalizes a reference URL for deduplication across sources.
// Scheme and host are lowercased; fragment is stripped; trailing path slash is
// removed; query parameters are lexicographically sorted.
func canonicalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = "/"
	}
	if u.RawQuery != "" {
		u.RawQuery = u.Query().Encode()
	}
	return u.String()
}
