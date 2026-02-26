package feed

import (
	"bytes"
	"regexp"
	"strings"
	"time"
)

// timeLayouts is the ordered list of timestamp formats encountered in CVE feeds.
// Never call time.Parse(time.RFC3339, val) directly on feed data — upstream
// sources are inconsistent about timezone suffixes and sub-second precision.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// ParseTime parses a feed timestamp using a multi-layout fallback. Returns a
// zero time.Time (not an error) on failure so callers can use nil-pointer
// semantics with a simple zero check.
func ParseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ParseTimePtr is like ParseTime but returns nil for zero/empty input.
func ParseTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t := ParseTime(s)
	if t.IsZero() {
		return nil
	}
	return &t
}

// StripNullBytes removes null bytes (\x00) from a string. Postgres TEXT and
// JSONB columns reject null bytes (implementation-pitfalls.md §2.10).
func StripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// StripNullBytesJSON removes null bytes from a JSON byte slice.
func StripNullBytesJSON(b []byte) []byte {
	return bytes.ReplaceAll(b, []byte{0}, []byte{})
}

// cveIDPattern matches CVE IDs in the canonical format CVE-YYYY-NNNNN+.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d+$`)

// ResolveCanonicalID returns a CVE ID from the aliases slice if one is present,
// otherwise returns nativeID unchanged. This is required for OSV and GHSA records
// where the native ID (GHSA-*, PYSEC-*, etc.) is an alias and the CVE ID should
// be used as the canonical primary key to prevent split-brain records.
//
// The nativeID is returned as-is when no CVE alias is found (the record will be
// stored under its own ID and merged if a CVE alias is discovered later via
// late-binding PK migration).
func ResolveCanonicalID(nativeID string, aliases []string) string {
	for _, alias := range aliases {
		if cveIDPattern.MatchString(alias) {
			return alias
		}
	}
	return nativeID
}
