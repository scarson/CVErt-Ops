// ABOUTME: Tier resolution middleware — loads org tier from DB and injects Resolver into context.
// ABOUTME: Must run after RequireOrgRole (which sets ctxOrgID).
package api

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
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
