// ABOUTME: Parses GHSA vulnerable_version_range strings into OSV-style range bounds.
// ABOUTME: Handles every form in the reviewed advisory corpus; anything else is reported as unparsed.
package ghsa

import (
	"encoding/json"

	"github.com/scarson/cvert-ops/internal/version"
)

// rangeBounds holds one range in OSV terms. Fixed and LastAffected are never both set.
type rangeBounds struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// parseVulnerableRange maps a GHSA range and first patched version to range bounds,
// by the rules of version.ParseRangeExpression.
// It returns false for a string it cannot read, so the caller keeps the package
// with no bounds and the version check answers "cannot evaluate".
func parseVulnerableRange(eco, raw, firstPatched string) (rangeBounds, bool) {
	r, ok := version.ParseRangeExpression(eco, raw, firstPatched)
	return rangeBounds(r), ok
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
