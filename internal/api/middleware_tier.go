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

		tierName, overrides, err := srv.store.GetOrgTier(r.Context(), orgID)
		if err != nil {
			slog.ErrorContext(r.Context(), "tier middleware: failed to load org tier",
				"org_id", orgID, "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		resolver := &tier.Resolver{Tier: tierName, Overrides: overrides}
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
		ratePerMin := 60
		if resolver, ok := r.Context().Value(ctxTierResolver).(*tier.Resolver); ok {
			ratePerMin = resolver.IntLimit("api_rate_limit", 60, 300, 1000)
		}

		ratePerSec := rate.Limit(float64(ratePerMin) / 60.0)
		if !srv.orgRL.Allow(orgID, ratePerSec, ratePerMin) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}
