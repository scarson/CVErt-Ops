// ABOUTME: GET /api/v1/whoami describes the calling credential: for an API key, the key, its org,
// ABOUTME: the role it acts with, the org's tier and rate limit; for a session, each org the user is active in.
package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// callerIdentity describes the credential that made the request.
type callerIdentity struct {
	Principal string        `json:"principal" enum:"api_key,session" doc:"api_key for a Bearer API key, session for a browser session cookie."`
	UserID    string        `json:"user_id" format:"uuid" doc:"The user the request acts as. For an API key, the user who created it."`
	APIKey    *callerAPIKey `json:"api_key,omitempty" doc:"The calling key. Present only when principal is api_key."`
	Org       *callerOrg    `json:"org,omitempty" doc:"The org the key belongs to; a key can reach no other org. Present only when principal is api_key."`
	Orgs      []callerOrg   `json:"orgs,omitempty" doc:"Each org where the user's membership is active, by name. Present only when principal is session."`
}

// callerAPIKey is the calling key's metadata. It never includes the key or its hash.
type callerAPIKey struct {
	ID        string  `json:"id" format:"uuid" doc:"API key ID."`
	Name      string  `json:"name" doc:"The name given when the key was created."`
	Role      string  `json:"role" enum:"viewer,member,admin" doc:"The highest role the key may act with. org.role is this, lowered to the creator's current org role."`
	ExpiresAt *string `json:"expires_at" format:"date-time" doc:"When the key stops working; null when it does not expire."`
}

// callerOrg is an org the caller can act in, with the role, tier and rate limit that apply.
type callerOrg struct {
	ID        string          `json:"id" format:"uuid" doc:"Organization ID, for /orgs/{org_id} paths."`
	Name      string          `json:"name" doc:"Organization name."`
	Role      string          `json:"role" enum:"viewer,member,admin,owner" doc:"The role requests act with in this org."`
	Tier      string          `json:"tier" doc:"The org's subscription tier."`
	RateLimit callerRateLimit `json:"rate_limit" doc:"The API rate limit that applies to requests in this org."`
}

// callerRateLimit is a token bucket: it refills at requests_per_minute and holds at most burst.
type callerRateLimit struct {
	Scope             string `json:"scope" enum:"org" doc:"Who shares the bucket. org: every key and session acting in the org."`
	RequestsPerMinute int    `json:"requests_per_minute" doc:"Sustained requests a minute."`
	Burst             int    `json:"burst" doc:"Requests that may be sent at once when the bucket is full."`
}

// whoamiHandler handles GET /api/v1/whoami. A key caller's request counts against its
// org's rate limit, as any request to an org route does.
func (srv *Server) whoamiHandler(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if keyID, ok := r.Context().Value(ctxAPIKeyID).(uuid.UUID); ok {
		srv.whoamiForAPIKey(w, r, userID, keyID)
		return
	}
	srv.whoamiForSession(w, r, userID)
}

func (srv *Server) whoamiForAPIKey(w http.ResponseWriter, r *http.Request, userID, keyID uuid.UUID) {
	ctx := r.Context()
	orgID, ok := ctx.Value(ctxAPIKeyOrgID).(uuid.UUID)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	keyRole, _ := ctx.Value(ctxAPIKeyRole).(string)

	org, err := srv.describeOrg(ctx, orgID, userID, keyRole)
	if err != nil {
		slog.ErrorContext(ctx, "whoami: describe key org", "org_id", orgID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	if org == nil {
		// The creator's membership is gone or deactivated: every org route refuses this key.
		writeProblem(w, http.StatusForbidden, "forbidden")
		return
	}
	if !srv.allowOrgRequest(w, orgID, orgRateLimitFromPerMinute(org.RateLimit.RequestsPerMinute)) {
		return
	}

	key, err := srv.store.GetOrgAPIKey(ctx, orgID, keyID)
	if err != nil || key == nil {
		slog.ErrorContext(ctx, "whoami: get api key", "key_id", keyID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	apiKey := &callerAPIKey{ID: key.ID.String(), Name: key.Name, Role: key.Role}
	if key.ExpiresAt.Valid {
		s := key.ExpiresAt.Time.UTC().Format(time.RFC3339)
		apiKey.ExpiresAt = &s
	}
	writeJSON(w, http.StatusOK, callerIdentity{
		Principal: "api_key",
		UserID:    userID.String(),
		APIKey:    apiKey,
		Org:       org,
	})
}

func (srv *Server) whoamiForSession(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	ctx := r.Context()
	memberships, err := srv.store.ListUserOrgs(ctx, userID)
	if err != nil {
		slog.ErrorContext(ctx, "whoami: list user orgs", "error", err)
		writeProblem(w, http.StatusInternalServerError, "internal error")
		return
	}
	orgs := make([]callerOrg, 0, len(memberships))
	for _, m := range memberships {
		org, err := srv.describeOrg(ctx, m.OrgID, userID, "")
		if err != nil {
			slog.ErrorContext(ctx, "whoami: describe org", "org_id", m.OrgID, "error", err)
			writeProblem(w, http.StatusInternalServerError, "internal error")
			return
		}
		if org != nil {
			orgs = append(orgs, *org)
		}
	}
	writeJSON(w, http.StatusOK, callerIdentity{
		Principal: "session",
		UserID:    userID.String(),
		Orgs:      orgs,
	})
}

// describeOrg returns the org as userID acts in it, with the role capped to keyRole
// (empty for a session). It returns nil when the org is deleted or the user's
// membership is missing or deactivated.
func (srv *Server) describeOrg(ctx context.Context, orgID, userID uuid.UUID, keyRole string) (*callerOrg, error) {
	member, err := srv.store.GetOrgMemberRoleAndStatus(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if member == nil || member.DeactivatedAt.Valid {
		return nil, nil
	}
	org, err := srv.store.GetOrgByID(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org == nil || org.DeletedAt.Valid {
		return nil, nil
	}
	resolver, err := srv.orgTierResolver(ctx, orgID)
	if err != nil {
		return nil, err
	}
	limit := orgRateLimitFor(resolver)
	return &callerOrg{
		ID:   org.ID.String(),
		Name: org.Name,
		Role: capToKeyRole(parseRole(member.Role), keyRole).String(),
		Tier: resolver.Tier,
		RateLimit: callerRateLimit{
			Scope:             "org",
			RequestsPerMinute: limit.perMinute,
			Burst:             limit.burst,
		},
	}, nil
}
