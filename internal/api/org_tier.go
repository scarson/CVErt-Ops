// ABOUTME: HTTP handler for GET /api/v1/orgs/{org_id}/tier.
// ABOUTME: Returns the org's tier, resolved limits, and current usage counts.
package api

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/tier"
)

type limitEntry struct {
	Limit   *int  `json:"limit,omitempty"`
	Used    *int  `json:"used,omitempty"`
	Allowed *bool `json:"allowed,omitempty"`
}

type tierResponse struct {
	Tier   string                `json:"tier"`
	Limits map[string]limitEntry `json:"limits"`
}

// getOrgTierHandler handles GET /api/v1/orgs/{org_id}/tier.
// Returns the org's current tier, resolved limits (respecting overrides),
// and usage counts for countable resources.
func (srv *Server) getOrgTierHandler(w http.ResponseWriter, r *http.Request) {
	orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "bad request")
		return
	}

	resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver)
	if !ok {
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Resolve limits.
	maxAlertRules := resolver.ResolveInt(tier.LimitAlertRules)
	maxWatchlists := resolver.ResolveInt(tier.LimitWatchlists)
	maxMembers := resolver.ResolveInt(tier.LimitMembers)
	apiRateLimit := resolver.ResolveInt(tier.LimitAPIRate)
	channelsEmail := resolver.ResolveBool(tier.FlagChannelsEmail)
	channelsWebhook := resolver.ResolveBool(tier.FlagChannelsWebhook)

	// Fetch usage counts.
	alertCount, err := srv.store.CountAlertRulesByOrg(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get tier: count alert rules", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	watchlistCount, err := srv.store.CountWatchlistsByOrg(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get tier: count watchlists", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	memberCount, err := srv.store.CountMembersByOrg(r.Context(), orgID)
	if err != nil {
		slog.ErrorContext(r.Context(), "get tier: count members", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}

	alertCountInt := int(alertCount)
	watchlistCountInt := int(watchlistCount)
	memberCountInt := int(memberCount)

	limits := map[string]limitEntry{
		"max_alert_rules":  {Limit: &maxAlertRules, Used: &alertCountInt},
		"max_watchlists":   {Limit: &maxWatchlists, Used: &watchlistCountInt},
		"max_members":      {Limit: &maxMembers, Used: &memberCountInt},
		"api_rate_limit":   {Limit: &apiRateLimit},
		"channels_email":   {Allowed: &channelsEmail},
		"channels_webhook": {Allowed: &channelsWebhook},
	}

	writeJSON(w, http.StatusOK, tierResponse{
		Tier:   resolver.Tier,
		Limits: limits,
	})
}
