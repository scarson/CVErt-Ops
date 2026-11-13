// ABOUTME: Integration tests for GET /api/v1/whoami, which describes the calling credential.
// ABOUTME: Covers API-key callers (key, org, effective role, tier, rate limit) and browser sessions.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const whoamiTestSecret = "test-jwt-secret-whoami"

// whoamiFixture is one org with an owner, and a server that issues sessions for that owner.
type whoamiFixture struct {
	server  *httptest.Server
	api     *Server
	db      *testutil.TestDB
	orgID   uuid.UUID
	ownerID uuid.UUID
}

func newWhoamiFixture(t *testing.T) *whoamiFixture {
	t.Helper()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	org, err := db.CreateOrg(ctx, "Whoami Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	owner, err := db.CreateUser(ctx, "whoami-owner@example.test", "Owner", "fakehash", 1)
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, owner.ID, "owner"); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	srv := newAuthTestServer(t, whoamiTestSecret, db)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &whoamiFixture{server: ts, api: srv, db: db, orgID: org.ID, ownerID: owner.ID}
}

// createKey creates a key owned by the org's owner and returns the raw key and its ID.
func (f *whoamiFixture) createKey(t *testing.T, name, role string, expiresAt sql.NullTime) (string, uuid.UUID) {
	t.Helper()
	raw, hash, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := f.db.CreateAPIKey(context.Background(), f.orgID, f.ownerID, hash, name, role, expiresAt)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	return raw, key.ID
}

// whoamiBody is the response as a script would decode it.
type whoamiBody struct {
	Principal string `json:"principal"`
	UserID    string `json:"user_id"`
	APIKey    *struct {
		ID        string  `json:"id"`
		Name      string  `json:"name"`
		Role      string  `json:"role"`
		ExpiresAt *string `json:"expires_at"`
	} `json:"api_key"`
	Org  *whoamiOrgBody  `json:"org"`
	Orgs []whoamiOrgBody `json:"orgs"`
}

type whoamiOrgBody struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	Tier      string `json:"tier"`
	RateLimit struct {
		Scope             string `json:"scope"`
		RequestsPerMinute int    `json:"requests_per_minute"`
		Burst             int    `json:"burst"`
	} `json:"rate_limit"`
}

// get calls GET /api/v1/whoami with a key or a session cookie and returns the status and raw body.
func (f *whoamiFixture) get(t *testing.T, key, session string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+"/api/v1/whoami", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if session != "" {
		req.AddCookie(requestCookie("access_token", session))
	}
	resp, err := f.server.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body
}

func decodeWhoami(t *testing.T, body []byte) whoamiBody {
	t.Helper()
	var out whoamiBody
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode whoami: %v (body %s)", err, body)
	}
	return out
}

// TestWhoami_APIKey is the acceptance test: given only a base URL and a key, one call
// returns the key, its org, the role it acts with, the tier and the rate limit.
func TestWhoami_APIKey(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	raw, keyID := f.createKey(t, "patch-runner", "member", sql.NullTime{Time: expires, Valid: true})

	status, body := f.get(t, raw, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	got := decodeWhoami(t, body)

	if got.Principal != "api_key" {
		t.Errorf("principal = %q, want api_key", got.Principal)
	}
	if got.UserID != f.ownerID.String() {
		t.Errorf("user_id = %q, want %s", got.UserID, f.ownerID)
	}
	if got.APIKey == nil {
		t.Fatalf("api_key missing (body %s)", body)
	}
	if got.APIKey.ID != keyID.String() || got.APIKey.Name != "patch-runner" || got.APIKey.Role != "member" {
		t.Errorf("api_key = %+v, want id %s, name patch-runner, role member", *got.APIKey, keyID)
	}
	if got.APIKey.ExpiresAt == nil {
		t.Fatalf("api_key.expires_at = null, want %s", expires.Format(time.RFC3339))
	}
	if gotExp, err := time.Parse(time.RFC3339, *got.APIKey.ExpiresAt); err != nil || !gotExp.Equal(expires) {
		t.Errorf("api_key.expires_at = %q, want %s", *got.APIKey.ExpiresAt, expires.Format(time.RFC3339))
	}
	if got.Org == nil {
		t.Fatalf("org missing (body %s)", body)
	}
	// The owner's org role is capped by the key's member role.
	if got.Org.ID != f.orgID.String() || got.Org.Name != "Whoami Org" || got.Org.Role != "member" {
		t.Errorf("org = %+v, want id %s, name Whoami Org, role member", *got.Org, f.orgID)
	}
	if got.Org.Tier != "free" {
		t.Errorf("org.tier = %q, want free", got.Org.Tier)
	}
	if got.Org.RateLimit.Scope != "org" || got.Org.RateLimit.RequestsPerMinute != 60 || got.Org.RateLimit.Burst != 10 {
		t.Errorf("org.rate_limit = %+v, want scope org, 60/min, burst 10", got.Org.RateLimit)
	}
	if got.Orgs != nil {
		t.Errorf("orgs = %+v, want absent for a key caller", got.Orgs)
	}
}

// TestWhoami_APIKeyNoExpiryAndTierOverride checks a never-expiring key and a tier
// whose rate limit comes from an org override.
func TestWhoami_APIKeyNoExpiryAndTierOverride(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	ctx := context.Background()
	if err := f.db.UpdateOrgTier(ctx, f.orgID, "pro"); err != nil {
		t.Fatalf("set tier: %v", err)
	}
	if _, err := f.db.DB().ExecContext(ctx,
		`UPDATE organizations SET tier_overrides = '{"api_rate_limit": 120}' WHERE id = $1`, f.orgID); err != nil {
		t.Fatalf("set override: %v", err)
	}
	raw, _ := f.createKey(t, "forever", "admin", sql.NullTime{})

	status, body := f.get(t, raw, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	got := decodeWhoami(t, body)
	if got.APIKey == nil || got.APIKey.ExpiresAt != nil {
		t.Errorf("api_key = %+v, want expires_at null", got.APIKey)
	}
	if got.Org == nil {
		t.Fatalf("org missing (body %s)", body)
	}
	if got.Org.Role != "admin" || got.Org.Tier != "pro" {
		t.Errorf("org = %+v, want role admin, tier pro", *got.Org)
	}
	if got.Org.RateLimit.RequestsPerMinute != 120 || got.Org.RateLimit.Burst != 20 {
		t.Errorf("org.rate_limit = %+v, want 120/min, burst 20", got.Org.RateLimit)
	}
}

// TestWhoami_Session describes a browser session: the user and each org it may act in.
func TestWhoami_Session(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	ctx := context.Background()
	// A second org where the membership is deactivated is left out.
	other, err := f.db.CreateOrg(ctx, "Left Org")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := f.db.CreateOrgMember(ctx, other.ID, f.ownerID, "viewer"); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := f.db.DB().ExecContext(ctx,
		`UPDATE org_members SET deactivated_at = now() WHERE org_id = $1 AND user_id = $2`, other.ID, f.ownerID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	session, err := auth.IssueAccessToken([]byte(whoamiTestSecret), f.ownerID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	status, body := f.get(t, "", session)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", status, body)
	}
	got := decodeWhoami(t, body)
	if got.Principal != "session" || got.UserID != f.ownerID.String() {
		t.Errorf("principal, user_id = %q, %q; want session, %s", got.Principal, got.UserID, f.ownerID)
	}
	if got.APIKey != nil || got.Org != nil {
		t.Errorf("api_key, org = %+v, %+v; want both absent for a session", got.APIKey, got.Org)
	}
	if len(got.Orgs) != 1 {
		t.Fatalf("orgs = %+v, want only the active membership", got.Orgs)
	}
	o := got.Orgs[0]
	if o.ID != f.orgID.String() || o.Role != "owner" || o.Tier != "free" || o.RateLimit.RequestsPerMinute != 60 {
		t.Errorf("orgs[0] = %+v, want the owner's free org at 60/min", o)
	}
}

// TestWhoami_Unauthenticated refuses a caller with no credential or a bad key.
func TestWhoami_Unauthenticated(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	if status, body := f.get(t, "", ""); status != http.StatusUnauthorized {
		t.Errorf("no credential: status = %d, want 401 (body %s)", status, body)
	}
	if status, body := f.get(t, "cvo_not-a-real-key", ""); status != http.StatusUnauthorized {
		t.Errorf("bad key: status = %d, want 401 (body %s)", status, body)
	}
}

// TestWhoami_APIKeyDeactivatedMembership refuses a key whose creator's membership in
// its org is deactivated, as every org route does.
func TestWhoami_APIKeyDeactivatedMembership(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	raw, _ := f.createKey(t, "orphan", "viewer", sql.NullTime{})
	if _, err := f.db.DB().ExecContext(context.Background(),
		`UPDATE org_members SET deactivated_at = now() WHERE org_id = $1 AND user_id = $2`, f.orgID, f.ownerID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if status, body := f.get(t, raw, ""); status != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (body %s)", status, body)
	}
}

// TestWhoami_APIKeyCountsAgainstOrgRateLimit spends from the org's bucket, so a key
// cannot use whoami to call past its org's limit.
func TestWhoami_APIKeyCountsAgainstOrgRateLimit(t *testing.T) {
	t.Parallel()
	f := newWhoamiFixture(t)
	// 6 requests a minute: a burst of 1, and the next token after 10 seconds, so the
	// second call is refused however slowly the test machine runs.
	if _, err := f.db.DB().ExecContext(context.Background(),
		`UPDATE organizations SET tier_overrides = '{"api_rate_limit": 6}' WHERE id = $1`, f.orgID); err != nil {
		t.Fatalf("set rate limit: %v", err)
	}
	raw, _ := f.createKey(t, "busy", "viewer", sql.NullTime{})
	if status, body := f.get(t, raw, ""); status != http.StatusOK {
		t.Fatalf("call 1: status = %d, want 200 (body %s)", status, body)
	}
	if status, _ := f.get(t, raw, ""); status != http.StatusTooManyRequests {
		t.Errorf("call 2: status = %d, want 429", status)
	}
}
