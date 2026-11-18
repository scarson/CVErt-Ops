// ABOUTME: Picks an advisory's fixed_version: the lowest candidate no range or CNA entry still reports (design section 7).
// ABOUTME: Also states fix_major, whether the version and the fix share their leading number.
package check

import (
	"regexp"
	"slices"
	"strings"

	"github.com/scarson/cvert-ops/internal/version"
)

// The fix_major values.
const (
	fixMajorSame      = "same"
	fixMajorDifferent = "different"
	fixMajorUnknown   = "unknown"
)

var (
	// epoch is a dpkg or RPM epoch, as in 1:2.0.
	epoch = regexp.MustCompile(`^[0-9]+:`)
	// pep440Epoch is a PEP 440 epoch, as in 1!2.0.
	pep440Epoch   = regexp.MustCompile(`^[0-9]+!`)
	leadingDigits = regexp.MustCompile(`^[0-9]+`)
)

// PickFix returns the lowest version the advisory data no longer reports as
// affecting ver, by design section 7:
//
//  1. candidates are the upper bounds of the ranges reporting ver as Affected;
//  2. they are ordered by order, and if order cannot read any of them no
//     minimum can be established, so there is no fix;
//  3. the lowest candidate is taken for which every range in ranges answers
//     NotAffected, and cna (when non-nil) reports neither Affected nor
//     Indeterminate;
//  4. if none passes, there is no fix.
//
// order is nil for an ecosystem with no comparator, which gives no fix. fixMajor
// is non-nil exactly when fixed is non-empty.
//
// It calls m.Tick once per range check and once per cna call, and returns no
// fix as soon as Tick refuses; the caller then reports m.Err.
func PickFix(m *workMeter, ver string, candidates []string, order version.Order, ranges []Bound,
	cna func(candidate string) Reading) (fixed string, fixMajor *string) {
	sorted, ok := sortCandidates(candidates, order)
	if !ok {
		return "", nil
	}
	for _, c := range sorted {
		passes, ok := candidatePasses(m, c, ranges, cna)
		if !ok {
			return "", nil
		}
		if passes {
			major := fixMajorOf(ver, c)
			return c, &major
		}
	}
	return "", nil
}

// sortCandidates returns the distinct candidates, lowest first, or false when
// there are none or order cannot read one of them. Candidates order reads as
// equal (1.2 and 1.2.0 numerically) are kept once, in their first spelling.
func sortCandidates(candidates []string, order version.Order) ([]string, bool) {
	if order == nil || len(candidates) == 0 {
		return nil, false
	}
	for _, c := range candidates {
		// Comparing a candidate with itself validates it, so a lone
		// unreadable candidate is caught too.
		if _, err := order(c, c); err != nil {
			return nil, false
		}
	}
	readable := true
	sorted := slices.Clone(candidates)
	slices.SortStableFunc(sorted, func(a, b string) int {
		c, err := order(a, b)
		if err != nil {
			readable = false
		}
		return c
	})
	if !readable {
		return nil, false
	}
	return slices.CompactFunc(sorted, func(a, b string) bool {
		c, _ := order(a, b) // both were read above
		return c == 0
	}), true
}

// candidatePasses reports whether every range answers NotAffected for candidate
// and cna reports neither Affected nor Indeterminate. Checks stop at the first
// that rejects. The second result is false when the meter refused.
func candidatePasses(m *workMeter, candidate string, ranges []Bound, cna func(string) Reading) (passes, ok bool) {
	for _, b := range ranges {
		if !m.Tick() {
			return false, false
		}
		// Affected and CannotEvaluate both reject; the error says only why.
		if status, _ := b.Check(candidate, b.Range); status != version.NotAffected {
			return false, true
		}
	}
	if cna == nil {
		return true, true
	}
	if !m.Tick() {
		return false, false
	}
	r := cna(candidate)
	return r != AffectedReading && r != Indeterminate, true
}

// fixMajorOf returns fix_major for a version and its fix: same when they share
// their leading number, different when they do not, unknown when either has
// none. It does not claim a release line: 8.4 to 8.5 is same.
func fixMajorOf(ver, fix string) string {
	a, aok := leadingNumber(ver)
	b, bok := leadingNumber(fix)
	switch {
	case !aok || !bok:
		return fixMajorUnknown
	case a == b:
		return fixMajorSame
	default:
		return fixMajorDifferent
	}
}

// leadingNumber returns the digits a version starts with, without leading zeros,
// after any epoch (1:2.0, or PEP 440's 1!2.0) and one v or V before a digit, as
// Go module versions are written (v1.2.3). Values can be longer than any integer
// type, so they are compared as digit strings.
func leadingNumber(v string) (string, bool) {
	v = strings.TrimPrefix(v, epoch.FindString(v))
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	v = strings.TrimPrefix(v, pep440Epoch.FindString(v))
	digits := leadingDigits.FindString(v)
	if digits == "" {
		return "", false
	}
	if trimmed := strings.TrimLeft(digits, "0"); trimmed != "" {
		return trimmed, true
	}
	return "0", true
}
