// Package feed defines shared canonical types used by all CVE feed adapters
// and the merge pipeline. Concrete adapter implementations live in
// subdirectories (mitre, nvd, osv, ghsa, kev, epss).
package feed

import (
	"context"
	"encoding/json"
	"time"
)

// Adapter is the interface implemented by every CVE feed adapter.
// Fetch returns one page of canonical patches and a cursor for the next page.
// A nil NextCursor in FetchResult signals no more pages.
//
// The type name is Adapter (not FeedAdapter) to avoid the feed.FeedAdapter stutter.
type Adapter interface {
	Fetch(ctx context.Context, cursor json.RawMessage) (*FetchResult, error)
}

// FetchResult is the return value of Adapter.Fetch.
type FetchResult struct {
	// Patches is the canonical CVE data for this page.
	Patches []CanonicalPatch
	// RawPayload is the unmodified upstream response for audit/debugging.
	// May be nil if the adapter does not retain raw payloads.
	RawPayload json.RawMessage
	// SourceMeta contains metadata about the fetch operation.
	SourceMeta SourceMeta
	// NextCursor is the opaque cursor for the next Fetch call.
	// Nil means no additional pages; the caller should persist the cursor
	// as the new sync state.
	NextCursor json.RawMessage
}

// SourceMeta records metadata about a single fetch operation.
type SourceMeta struct {
	SourceName string
	FetchedAt  time.Time
	RequestID  string // correlation ID from upstream response headers, if any
}

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
