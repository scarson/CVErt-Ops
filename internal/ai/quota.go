// ABOUTME: Quota resolution logic for AI features.
// ABOUTME: Resolves per-org overrides > tier defaults > hardcoded fallbacks.
package ai

// TierLimits holds the daily request limits per tier for one AI feature.
type TierLimits struct {
	Free       int
	Pro        int
	Enterprise int
}

// ResolveLimit returns the effective daily limit. Precedence:
// per-org override > tier default > Free fallback.
func ResolveLimit(override int, hasOverride bool, tierLimits TierLimits, orgTier string) int {
	if hasOverride {
		return override
	}
	switch orgTier {
	case "pro":
		return tierLimits.Pro
	case "enterprise":
		return tierLimits.Enterprise
	default:
		return tierLimits.Free
	}
}
