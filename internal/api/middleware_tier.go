// ABOUTME: Tier resolution middleware and per-org rate limiting middleware.
// ABOUTME: Must run after RequireOrgRole (which sets ctxOrgID).
package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/tier"
)

// tierMiddleware loads the org's tier and overrides from the store and injects
// a *tier.Resolver into the request context. Downstream handlers read the
// resolver via ctxTierResolver.
func (srv *Server) tierMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
		if !ok {
			// No org context — skip tier resolution (should not happen after RequireOrgRole).
			next.ServeHTTP(w, r)
			return
		}

		resolver, err := srv.orgTierResolver(r.Context(), orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "tier middleware: failed to load org tier",
				"org_id", orgID, "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal server error")
			return
		}

		ctx := context.WithValue(r.Context(), ctxTierResolver, resolver)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// orgRateLimitMiddleware enforces per-org API rate limits. Must run after
// tierMiddleware (which sets ctxTierResolver) and RequireOrgRole (which sets ctxOrgID).
func (srv *Server) orgRateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		// Resolve rate from tier; default free=60, pro=300, enterprise=1000 req/min.
		limit := orgRateLimitFromPerMinute(60)
		if resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver); ok {
			limit = orgRateLimitFor(resolver)
		}
		if !srv.allowOrgRequest(w, orgID, limit) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

// orgTierResolver returns a resolver for the org's tier and overrides, read from the
// tier cache when it holds them and from the store otherwise.
func (srv *Server) orgTierResolver(ctx context.Context, orgID uuid.UUID) (*tier.Resolver, error) {
	tierName, overrides, cached := srv.tierCache.Get(orgID)
	if !cached {
		var err error
		tierName, overrides, err = srv.store.GetOrgTier(ctx, orgID)
		if err != nil {
			return nil, err
		}
		srv.tierCache.Set(orgID, tierName, overrides)
	}
	return &tier.Resolver{Tier: tierName, Overrides: overrides}, nil
}

// orgRateLimit is an org's API rate limit: a token bucket refilled at perMinute
// requests a minute that holds at most burst tokens.
type orgRateLimit struct {
	perMinute int
	burst     int
}

// orgRateLimitFor returns the API rate limit of the resolver's tier.
func orgRateLimitFor(resolver *tier.Resolver) orgRateLimit {
	return orgRateLimitFromPerMinute(resolver.ResolveInt(tier.LimitAPIRate))
}

// orgRateLimitFromPerMinute sets the burst to about ten seconds of requests, and at least one.
func orgRateLimitFromPerMinute(perMinute int) orgRateLimit {
	return orgRateLimit{perMinute: perMinute, burst: max(perMinute/6, 1)}
}

// allowOrgRequest spends one request from the org's bucket. When the bucket is
// empty it writes a 429 and returns false.
func (srv *Server) allowOrgRequest(w http.ResponseWriter, orgID uuid.UUID, limit orgRateLimit) bool {
	if srv.orgRL.Allow(orgID, rate.Limit(float64(limit.perMinute)/60.0), limit.burst) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded")
	return false
}
