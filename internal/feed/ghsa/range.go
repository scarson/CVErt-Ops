// ABOUTME: Parses GHSA vulnerable_version_range strings into OSV-style range bounds.
// ABOUTME: Handles every form in the reviewed advisory corpus; anything else is reported as unparsed.
package ghsa

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/scarson/cvert-ops/internal/version"
)

// rangeBounds holds one range in OSV terms. Fixed and LastAffected are never both set.
type rangeBounds struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

var (
	rangeConstraint = regexp.MustCompile(`^(>=|<=|>|<|=)\s*([^\s<>=]\S*)$`)
	zeroVersion     = regexp.MustCompile(`^0+(\.0+)*$`)
)

// parseVulnerableRange maps a GHSA range and first patched version to range bounds.
// It returns false for a string it cannot read, so the caller keeps the package
// with no bounds and the version check answers "cannot evaluate".
//
// An exclusive upper bound is used as given, because the range is what GHSA states
// is vulnerable. An inclusive upper bound yields to the first patched version when
// that version sorts above it, as OSV's copies of these advisories do; versions
// between the two report as affected. If the order cannot be proven, the declared
// bound stands, because shortening a declared range could report "not affected". An
// exclusive lower bound is stored inclusively, because a range has no exclusive lower
// bound, so that one version reports as affected.
func parseVulnerableRange(eco, raw, firstPatched string) (rangeBounds, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if firstPatched == "" {
			return rangeBounds{}, false
		}
		return rangeBounds{Introduced: "0", Fixed: firstPatched}, true
	}

	parts := strings.Split(raw, ",")
	if len(parts) > 2 {
		return rangeBounds{}, false
	}

	var lower, exact, exclusiveUpper, inclusiveUpper string
	for _, part := range parts {
		m := rangeConstraint.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			return rangeBounds{}, false
		}
		switch op, value := m[1], m[2]; op {
		case ">=", ">":
			if lower != "" {
				return rangeBounds{}, false
			}
			lower = value
		case "<":
			if exclusiveUpper != "" || inclusiveUpper != "" {
				return rangeBounds{}, false
			}
			exclusiveUpper = value
		case "<=":
			if exclusiveUpper != "" || inclusiveUpper != "" {
				return rangeBounds{}, false
			}
			inclusiveUpper = value
		case "=":
			if len(parts) != 1 {
				return rangeBounds{}, false
			}
			exact = value
		}
	}

	patchedAbove := func(bound string) bool {
		if firstPatched == "" {
			return false
		}
		c, err := version.Compare(eco, firstPatched, bound)
		return err == nil && c > 0
	}

	if exact != "" {
		if patchedAbove(exact) {
			return rangeBounds{Introduced: exact, Fixed: firstPatched}, true
		}
		return rangeBounds{Introduced: exact, LastAffected: exact}, true
	}

	bounds := rangeBounds{Introduced: "0"}
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

// boundsEvents returns OSV-format events for bounds, or nil when there are none.
func boundsEvents(b rangeBounds) json.RawMessage {
	if b.Introduced == "" {
		return nil
	}
	type event struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	}
	events := []event{{Introduced: b.Introduced}}
	if b.Fixed != "" || b.LastAffected != "" {
		events = append(events, event{Fixed: b.Fixed, LastAffected: b.LastAffected})
	}
	raw, err := json.Marshal(events)
	if err != nil {
		return nil
	}
	return raw
}
