// ABOUTME: RequireOrgRole middleware — enforces org membership and minimum RBAC role.
// ABOUTME: Caps effective role to the minimum of the org role and any API key role.
package api

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// RequireOrgRole returns a middleware that verifies the authenticated user is a
// member of the org in the URL ({org_id}) with at least minRole. For API key
// requests the effective role is capped to min(orgRole, apiKeyRole). On success
// it injects ctxOrgID and ctxRole into the request context.
//
// Must run after RequireAuthenticated.
func (srv *Server) RequireOrgRole(minRole Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
			if !ok {
				writeProblem(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			orgID, err := uuid.Parse(chi.URLParam(r, "org_id"))
			if err != nil {
				writeProblem(w, http.StatusBadRequest, "invalid org_id")
				return
			}

			// API keys are scoped to their org — reject if the request targets a different org.
			if apiKeyOrgID, ok := r.Context().Value(ctxAPIKeyOrgID).(uuid.UUID); ok {
				if apiKeyOrgID != orgID {
					writeProblem(w, http.StatusForbidden, "api key not valid for this organization")
					return
				}
			}

			roleStr, err := srv.store.GetOrgMemberRole(r.Context(), orgID, userID)
			if err != nil || roleStr == nil {
				writeProblem(w, http.StatusForbidden, "forbidden")
				return
			}

			effectiveRole := parseRole(*roleStr)

			// Cap effective role to the API key's role when the request is API-key-authenticated.
			if apiKeyRoleStr, ok := r.Context().Value(ctxAPIKeyRole).(string); ok && apiKeyRoleStr != "" {
				if keyRole := parseRole(apiKeyRoleStr); keyRole < effectiveRole {
					effectiveRole = keyRole
				}
			}

			if effectiveRole < minRole {
				writeProblem(w, http.StatusForbidden, "forbidden")
				return
			}

			ctx := context.WithValue(r.Context(), ctxOrgID, orgID)
			ctx = context.WithValue(ctx, ctxRole, effectiveRole)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
