package merge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	jsoncanonical "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

// MaterialFields contains all fields that contribute to material_hash. Any
// change to these fields triggers a new hash, which bumps date_modified_canonical
// and fires real-time alert evaluation.
//
// epss_score is explicitly excluded per PLAN.md §5.3 — EPSS changes do not
// represent a material change to the CVE record itself.
type MaterialFields struct {
	Status         string              `json:"status"`
	Severity       string              `json:"severity"`
	CVSSv3Score    *float64            `json:"cvss_v3_score,omitempty"`
	CVSSv3Vector   string              `json:"cvss_v3_vector"`
	CVSSv4Score    *float64            `json:"cvss_v4_score,omitempty"`
	CVSSv4Vector   string              `json:"cvss_v4_vector"`
	CWEIDs         []string            `json:"cwe_ids"`
	ExploitAvail   bool                `json:"exploit_available"`
	InCISAKEV      bool                `json:"in_cisa_kev"`
	AffectedPkgs   []affectedPkgKey    `json:"affected_packages"`
	AffectedCPEs   []string            `json:"affected_cpes"`
}

// affectedPkgKey is the minimal key used to represent a package version range
// in the material hash. Complex event arrays are not included — only the
// fields that identify a distinct affected version range.
type affectedPkgKey struct {
	Ecosystem   string `json:"ecosystem"`
	PackageName string `json:"package_name"`
	Introduced  string `json:"introduced,omitempty"`
	Fixed       string `json:"fixed,omitempty"`
}

// ComputeMaterialHash returns the hex-encoded SHA-256 of the JCS (RFC 8785)
// serialization of f. Before hashing:
//   - CVSS vectors are normalized to canonical metric order
//   - All string slice fields are sorted lexicographically
//   - affectedPkgs is sorted by (ecosystem, package_name, introduced)
func ComputeMaterialHash(f MaterialFields) string {
	// Normalize CVSS vectors to canonical metric order.
	f.CVSSv3Vector = normalizeCVSSVector(f.CVSSv3Vector)
	f.CVSSv4Vector = normalizeCVSSVector(f.CVSSv4Vector)

	// Sort all slice fields so hash is independent of insertion order.
	sort.Strings(f.CWEIDs)
	sort.Strings(f.AffectedCPEs)
	sort.Slice(f.AffectedPkgs, func(i, j int) bool {
		a, b := f.AffectedPkgs[i], f.AffectedPkgs[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.PackageName != b.PackageName {
			return a.PackageName < b.PackageName
		}
		return a.Introduced < b.Introduced
	})

	// Nil slices → empty slices so JCS produces "[]" not "null".
	if f.CWEIDs == nil {
		f.CWEIDs = []string{}
	}
	if f.AffectedCPEs == nil {
		f.AffectedCPEs = []string{}
	}
	if f.AffectedPkgs == nil {
		f.AffectedPkgs = []affectedPkgKey{}
	}

	raw, err := json.Marshal(f)
	if err != nil {
		// json.Marshal on a struct with only basic types never fails.
		panic(fmt.Sprintf("merge: marshal material fields: %v", err))
	}

	jcs, err := jsoncanonical.Transform(raw)
	if err != nil {
		// JCS transform fails only on invalid JSON, which cannot happen here.
		panic(fmt.Sprintf("merge: JCS transform: %v", err))
	}

	sum := sha256.Sum256(jcs)
	return hex.EncodeToString(sum[:])
}

// normalizeCVSSVector reorders CVSS vector metrics to the canonical spec order
// so that semantically identical vectors with different metric orderings produce
// the same hash.
//
// CVSS v3.x vectors: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
// CVSS v4.0 vectors: "CVSS:4.0/AV:N/AC:L/..."
//
// We split on '/', sort the metric segments (after the version prefix), then
// rejoin. This is spec-order-independent but stable.
func normalizeCVSSVector(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, "/")
	if len(parts) < 2 {
		return v
	}
	// parts[0] is the version prefix (e.g., "CVSS:3.1"). Sort the rest.
	metrics := parts[1:]
	sort.Strings(metrics)
	return parts[0] + "/" + strings.Join(metrics, "/")
}
