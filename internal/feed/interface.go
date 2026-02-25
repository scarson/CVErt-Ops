// Package feed defines shared canonical types used by all CVE feed adapters
// and the merge pipeline. Concrete adapter implementations live in
// subdirectories (mitre, nvd, osv, ghsa, kev, epss). The FeedAdapter
// interface and FetchResult type are added in Phase 1 Commit 4.
package feed

import (
	"encoding/json"
	"time"
)

// CanonicalPatch is the normalized representation of CVE data from a single
// feed source. All adapters express their output as CanonicalPatch values
// that are passed to the merge pipeline for deduplication and persistence.
//
// Pointer fields allow missing data (nil) to be distinguished from an
// intentional zero value during per-field source precedence resolution.
type CanonicalPatch struct {
	CVEID              string            `json:"cve_id"`
	SourceID           string            `json:"source_id,omitempty"`
	Status             string            `json:"status,omitempty"`
	DatePublished      *time.Time        `json:"date_published,omitempty"`
	DateModified       *time.Time        `json:"date_modified,omitempty"`
	DescriptionPrimary *string           `json:"description_primary,omitempty"`
	Severity           *string           `json:"severity,omitempty"`
	CVSSv3Score        *float64          `json:"cvss_v3_score,omitempty"`
	CVSSv3Vector       *string           `json:"cvss_v3_vector,omitempty"`
	CVSSv4Score        *float64          `json:"cvss_v4_score,omitempty"`
	CVSSv4Vector       *string           `json:"cvss_v4_vector,omitempty"`
	CWEIDs             []string          `json:"cwe_ids,omitempty"`
	ExploitAvailable   *bool             `json:"exploit_available,omitempty"`
	InCISAKEV          *bool             `json:"in_cisa_kev,omitempty"`
	References         []ReferenceEntry  `json:"references,omitempty"`
	AffectedPackages   []AffectedPackage `json:"affected_packages,omitempty"`
	AffectedCPEs       []AffectedCPE     `json:"affected_cpes,omitempty"`
	IsWithdrawn        bool              `json:"is_withdrawn,omitempty"`
}

// ReferenceEntry is a single hyperlink reference associated with a CVE.
type ReferenceEntry struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags,omitempty"`
}

// AffectedPackage describes a version range within a package ecosystem
// that is affected by a CVE.
type AffectedPackage struct {
	Ecosystem    string          `json:"ecosystem"`
	PackageName  string          `json:"package_name"`
	Namespace    string          `json:"namespace,omitempty"`
	RangeType    string          `json:"range_type,omitempty"`
	Introduced   string          `json:"introduced,omitempty"`
	Fixed        string          `json:"fixed,omitempty"`
	LastAffected string          `json:"last_affected,omitempty"`
	Events       json.RawMessage `json:"events,omitempty"`
}

// AffectedCPE is a CPE (Common Platform Enumeration) string associated
// with a CVE. CPENormalized is a lowercase, consistently-formatted form
// used for deduplication across sources.
type AffectedCPE struct {
	CPE           string `json:"cpe"`
	CPENormalized string `json:"cpe_normalized"`
}
