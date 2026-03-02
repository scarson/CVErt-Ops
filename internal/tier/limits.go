// ABOUTME: Pre-defined tier limit and feature flag defaults for all gated resources.
// ABOUTME: Single source of truth — handlers resolve via Resolver.ResolveInt/ResolveBool.
package tier

// IntLimitDef defines the per-tier defaults for an integer limit.
type IntLimitDef struct {
	Key        string
	Free       int
	Pro        int
	Enterprise int
}

// BoolFlagDef defines the per-tier defaults for a boolean feature flag.
type BoolFlagDef struct {
	Key        string
	Free       bool
	Pro        bool
	Enterprise bool
}

// Pre-defined tier limits and feature flags. Values here are the single source
// of truth — gating handlers and the tier endpoint both resolve through these.
var (
	LimitAlertRules = IntLimitDef{"max_alert_rules", 5, 50, -1}
	LimitWatchlists = IntLimitDef{"max_watchlists", 3, 20, -1}
	LimitMembers    = IntLimitDef{"max_members", 5, 25, -1}
	LimitAPIRate    = IntLimitDef{"api_rate_limit", 60, 300, 1000}

	FlagChannelsEmail   = BoolFlagDef{"channels_email", false, true, true}
	FlagChannelsWebhook = BoolFlagDef{"channels_webhook", true, true, true}
)

// ResolveInt resolves an integer limit using the pre-defined defaults.
func (r *Resolver) ResolveInt(def IntLimitDef) int {
	return r.IntLimit(def.Key, def.Free, def.Pro, def.Enterprise)
}

// ResolveBool resolves a boolean flag using the pre-defined defaults.
func (r *Resolver) ResolveBool(def BoolFlagDef) bool {
	return r.BoolFlag(def.Key, def.Free, def.Pro, def.Enterprise)
}
