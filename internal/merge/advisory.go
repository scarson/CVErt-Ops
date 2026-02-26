// Package merge implements the CVE canonical merge pipeline.
// It reads all cve_sources rows for a CVE, resolves per-field precedence,
// computes the material_hash, and upserts the canonical cves row plus all
// child tables within a single advisory-locked transaction.
package merge

import (
	"hash/fnv"
)

// advisoryKey returns a stable int64 advisory lock key for the given domain
// and ID. The domain prefix prevents collisions between unrelated advisory
// lock users in the same database.
//
// Callers must use a consistent domain prefix:
//   - "cve" — merge pipeline and EPSS adapter (§5.3)
//
// Any future advisory lock user MUST use a different domain prefix to avoid
// colliding with the merge pipeline lock space.
func advisoryKey(domain, id string) int64 {
	h := fnv.New64a()
	// domain:id format ensures different domains never collide even if their
	// ids overlap (e.g., "cve:CVE-2024-1234" vs "org:CVE-2024-1234").
	// hash.Hash.Write is documented to never return an error; discard explicitly.
	_, _ = h.Write([]byte(domain + ":" + id))
	// Intentional uint64→int64 reinterpretation: advisory lock keys use the full
	// int64 range. Zeroing the sign bit would halve hash distribution unnecessarily.
	return int64(h.Sum64()) //nolint:gosec // G115: intentional full-range reinterpretation for advisory lock key
}

// CVEAdvisoryKey returns the advisory lock key for the given CVE ID. Used by
// both the merge pipeline and the EPSS adapter to serialize concurrent writes.
func CVEAdvisoryKey(cveID string) int64 {
	return advisoryKey("cve", cveID)
}
