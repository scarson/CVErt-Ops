// ABOUTME: Nil-safe field accessors for CVE records used in the alert evaluator's regex post-filter.
// ABOUTME: All accessors accept a nil pointer and return zero values safely.
package dsl

import (
	"strings"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CVSSV3Score returns the CVSS v3 base score, or 0 if the CVE or score is nil/absent.
func CVSSV3Score(c *generated.Cfe) float64 {
	if c == nil || !c.CvssV3Score.Valid {
		return 0
	}
	return c.CvssV3Score.Float64
}

// CVSSV4Score returns the CVSS v4 base score, or 0 if the CVE or score is nil/absent.
func CVSSV4Score(c *generated.Cfe) float64 {
	if c == nil || !c.CvssV4Score.Valid {
		return 0
	}
	return c.CvssV4Score.Float64
}

// EPSSScore returns the EPSS probability score, or 0 if the CVE or score is nil/absent.
func EPSSScore(c *generated.Cfe) float64 {
	if c == nil || !c.EpssScore.Valid {
		return 0
	}
	return c.EpssScore.Float64
}

// DescriptionPrimary returns the primary description in lowercase, or "" if nil/absent.
// Lowercased for case-insensitive regex matching in PostFilter evaluation.
func DescriptionPrimary(c *generated.Cfe) string {
	if c == nil || !c.DescriptionPrimary.Valid {
		return ""
	}
	return strings.ToLower(c.DescriptionPrimary.String)
}
