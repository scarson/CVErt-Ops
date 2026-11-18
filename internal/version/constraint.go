// ABOUTME: Reads comma-separated range expressions such as ">= 1.0, < 2.0" into a Range.
// ABOUTME: Covers GHSA vulnerable_version_range and the same grammar in CNA free text; anything else is unparsed.
package version

import (
	"regexp"
	"strings"
)

var (
	rangeConstraint = regexp.MustCompile(`^(>=|<=|>|<|=)\s*([^\s<>=]\S*)$`)
	zeroVersion     = regexp.MustCompile(`^0+(\.0+)*$`)
)

// ParseRangeExpression maps a range expression and an optional first patched
// version to a Range. It returns false for a string it cannot read. The first
// patched version is compared under the named ecosystem's ordering; an ecosystem
// with none, such as "", never proves that it sorts above a bound.
//
// An exclusive upper bound is used as given, because the range is what GHSA states
// is vulnerable. An inclusive upper bound yields to the first patched version when
// that version sorts above it, as OSV's copies of these advisories do; versions
// between the two report as affected. If the order cannot be proven, the declared
// bound stands, because shortening a declared range could report "not affected". An
// exclusive lower bound is stored inclusively, because a range has no exclusive lower
// bound, so that one version reports as affected.
func ParseRangeExpression(ecosystem, raw, firstPatched string) (Range, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if firstPatched == "" {
			return Range{}, false
		}
		return Range{Introduced: "0", Fixed: firstPatched}, true
	}

	parts := strings.Split(raw, ",")
	if len(parts) > 2 {
		return Range{}, false
	}

	var lower, exact, exclusiveUpper, inclusiveUpper string
	for _, part := range parts {
		m := rangeConstraint.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			return Range{}, false
		}
		switch op, value := m[1], m[2]; op {
		case ">=", ">":
			if lower != "" {
				return Range{}, false
			}
			lower = value
		case "<":
			if exclusiveUpper != "" || inclusiveUpper != "" {
				return Range{}, false
			}
			exclusiveUpper = value
		case "<=":
			if exclusiveUpper != "" || inclusiveUpper != "" {
				return Range{}, false
			}
			inclusiveUpper = value
		case "=":
			if len(parts) != 1 {
				return Range{}, false
			}
			exact = value
		}
	}

	patchedAbove := func(bound string) bool {
		if firstPatched == "" {
			return false
		}
		c, err := Compare(ecosystem, firstPatched, bound)
		return err == nil && c > 0
	}

	if exact != "" {
		if patchedAbove(exact) {
			return Range{Introduced: exact, Fixed: firstPatched}, true
		}
		return Range{Introduced: exact, LastAffected: exact}, true
	}

	bounds := Range{Introduced: "0"}
	if lower != "" && !zeroVersion.MatchString(lower) {
		bounds.Introduced = lower
	}
	switch {
	case exclusiveUpper != "":
		bounds.Fixed = exclusiveUpper
	case inclusiveUpper != "" && patchedAbove(inclusiveUpper):
		bounds.Fixed = firstPatched
	case inclusiveUpper != "":
		bounds.LastAffected = inclusiveUpper
	case bounds.Introduced == "0" || patchedAbove(bounds.Introduced):
		bounds.Fixed = firstPatched
	}
	return bounds, true
}
