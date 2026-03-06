// ABOUTME: Resolves tier-gated limits and feature flags for organizations.
// ABOUTME: Precedence: per-org override → tier default → free fallback.
package tier

// Resolver resolves tier-gated limits for a single organization.
type Resolver struct {
	Tier      string         // "free", "pro", "enterprise"
	Overrides map[string]any // from organizations.tier_overrides JSONB
}

// IntLimit returns the effective integer limit. -1 means unlimited.
func (r *Resolver) IntLimit(name string, free, pro, enterprise int) int {
	if r.Overrides != nil {
		if v, ok := r.Overrides[name]; ok {
			if f, ok := v.(float64); ok {
				return int(f)
			}
		}
	}
	switch r.Tier {
	case "pro":
		return pro
	case "enterprise":
		return enterprise
	default:
		return free
	}
}

// BoolFlag returns the effective boolean flag.
func (r *Resolver) BoolFlag(name string, free, pro, enterprise bool) bool {
	if r.Overrides != nil {
		if v, ok := r.Overrides[name]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
	}
	switch r.Tier {
	case "pro":
		return pro
	case "enterprise":
		return enterprise
	default:
		return free
	}
}
