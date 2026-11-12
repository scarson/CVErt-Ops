// ABOUTME: Checks each operation's declared security in the served spec against what the real server enforces.
// ABOUTME: Calls every operation with no credentials, API keys at each role, and browser sessions.
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/auth"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// sessionOnlyBodies holds a valid body for session-only huma operations: huma
// validates the body before the handler checks the cookie, so an empty request
// would be rejected for the wrong reason.
var sessionOnlyBodies = map[string]string{
	"POST /auth/change-password":               `{"new_password":"a-new-password-of-sufficient-length"}`,
	"DELETE /auth/mfa/methods/{method}":        `{"current_password":"not-the-password"}`,
	"POST /auth/mfa/recovery-codes/regenerate": `{"current_password":"not-the-password"}`,
}

// securityFixture is an org on the enterprise tier, so tier limits and rate
// limits do not answer in place of the checks under test, with credentials for
// each kind of caller.
type securityFixture struct {
	server    *httptest.Server
	api       *Server
	db        *testutil.TestDB
	orgID     uuid.UUID
	keys      map[string]string // API key by role
	session   string            // access token of the org's owner
	siteAdmin string            // access token of a site admin who is in no org
}

func newSecurityFixture(t *testing.T) *securityFixture {
	t.Helper()
	ctx := context.Background()
	db := testutil.NewTestDB(t)
	const secret = "test-jwt-secret-openapi-security"

	org, err := db.CreateOrg(ctx, "Security Conformance")
	if err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := db.UpdateOrgTier(ctx, org.ID, "enterprise"); err != nil {
		t.Fatalf("set tier: %v", err)
	}
	// One run sends hundreds of requests in seconds, past even the enterprise limit.
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE organizations SET tier_overrides = '{"api_rate_limit": 1000000}' WHERE id = $1`, org.ID); err != nil {
		t.Fatalf("raise rate limit: %v", err)
	}
	owner, err := db.CreateUser(ctx, "conformance-owner@example.test", "Owner", "fakehash", 1)
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := db.CreateOrgMember(ctx, org.ID, owner.ID, "owner"); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	keys := map[string]string{}
	for _, role := range []string{"viewer", "member", "admin", "owner"} {
		raw, hash, err := auth.GenerateAPIKey()
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if _, err := db.CreateAPIKey(ctx, org.ID, owner.ID, hash, role, role, sql.NullTime{}); err != nil {
			t.Fatalf("create %s key: %v", role, err)
		}
		keys[role] = raw
	}
	session, err := auth.IssueAccessToken([]byte(secret), owner.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue owner token: %v", err)
	}
	admin, err := db.CreateUser(ctx, "conformance-admin@example.test", "Admin", "fakehash", 1)
	if err != nil {
		t.Fatalf("create site admin: %v", err)
	}
	if err := db.SetFirstSiteAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("set site admin: %v", err)
	}
	siteAdmin, err := auth.IssueAccessToken([]byte(secret), admin.ID, 1, 15*time.Minute)
	if err != nil {
		t.Fatalf("issue site admin token: %v", err)
	}

	srv := newAuthTestServer(t, secret, db)
	// The test config leaves these per-user limits at zero, which refuses every request.
	srv.cfg.MFAEmailOTPMaxPerHour = 100
	srv.cfg.EmailVerificationMaxPerHour = 100
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &securityFixture{server: ts, api: srv, db: db, orgID: org.ID, keys: keys, session: session, siteAdmin: siteAdmin}
}

// fillPath substitutes path parameters. IDs are random, so a request that passes
// its authorization checks ends in a 404 or validation error rather than changing
// the fixture's org.
func (f *securityFixture) fillPath(path string) string {
	replacer := strings.NewReplacer(
		"{org_id}", f.orgID.String(),
		"{feed}", "nvd",
		"{cve_id}", "CVE-2024-0001",
		"{token}", "not-a-real-token",
		"{method}", "totp",
	)
	path = replacer.Replace(path)
	for strings.Contains(path, "{") {
		start, end := strings.Index(path, "{"), strings.Index(path, "}")
		path = path[:start] + uuid.NewString() + path[end+1:]
	}
	return path
}

// call sends one request and returns its status. withKey and withCookie are
// mutually exclusive credentials; both empty sends no credentials.
func (f *securityFixture) call(t *testing.T, op, withKey, withCookie string) int {
	t.Helper()
	method, path, _ := strings.Cut(op, " ")
	var body io.Reader
	if b, ok := sessionOnlyBodies[op]; ok {
		body = strings.NewReader(b)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+"/api/v1"+f.fillPath(path), body)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withKey != "" {
		req.Header.Set("Authorization", "Bearer "+withKey)
	}
	if withCookie != "" {
		req.AddCookie(requestCookie("access_token", withCookie))
		req.Header.Set("X-Requested-By", "CVErt-Ops")
	}
	resp, err := f.server.Client().Do(req) //nolint:gosec // G704: httptest server URL
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	defer resp.Body.Close()               //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck // drained so the connection is reused
	// A 429 answers before the check under test, so it proves nothing either way.
	if resp.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("%s: rate limited, so authorization was not exercised", op)
	}
	return resp.StatusCode
}

// declaredOperation is one operation's security as the served spec declares it.
type declaredOperation struct {
	name     string // "METHOD /path"
	schemes  []string
	minRole  string
	ownToken bool
}

// declaredOperations reads every operation's security from the served spec.
func declaredOperations(t *testing.T, handler http.Handler) []declaredOperation {
	t.Helper()
	spec := fetchSpec(t, handler, "/api/v1/openapi.json")
	var ops []declaredOperation
	for path, item := range spec["paths"].(map[string]any) {
		for method, raw := range item.(map[string]any) {
			op := raw.(map[string]any)
			declared := declaredOperation{name: strings.ToUpper(method) + " " + path}
			security, _ := op["security"].([]any)
			for _, requirement := range security {
				for scheme := range requirement.(map[string]any) {
					declared.schemes = append(declared.schemes, scheme)
				}
			}
			declared.minRole, _ = op["x-min-role"].(string)
			declared.ownToken, _ = op["x-own-credential"].(bool)
			ops = append(ops, declared)
		}
	}
	slices.SortFunc(ops, func(a, b declaredOperation) int { return strings.Compare(a.name, b.name) })
	return ops
}

// lowerRole returns the role one step below role, or "" for the lowest role.
func lowerRole(role string) string {
	return map[string]string{"member": "viewer", "admin": "member", "owner": "admin"}[role]
}

func deniedStatus(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// TestOpenAPISecurity_MatchesEnforcement is the check that the spec tells a client
// the truth: a client generated from it knows which credential each operation
// takes and which role it needs.
func TestOpenAPISecurity_MatchesEnforcement(t *testing.T) {
	t.Parallel()
	f := newSecurityFixture(t)
	ops := declaredOperations(t, f.server.Config.Handler)
	if len(ops) == 0 {
		t.Fatal("spec declares no operations")
	}

	for _, op := range ops {
		bearer := slices.Contains(op.schemes, "bearerAuth")
		cookie := slices.Contains(op.schemes, "cookieAuth")
		siteAdminOnly := op.minRole == roleSiteAdmin

		// Public operations, and those with their own credential cookie, have
		// nothing to check in this table.
		if !bearer && !cookie {
			if !op.ownToken {
				if status := f.call(t, op.name, "", ""); deniedStatus(status) {
					t.Errorf("%s: declared public but answered %d with no credentials", op.name, status)
				}
			}
			continue
		}

		if status := f.call(t, op.name, "", ""); status != http.StatusUnauthorized {
			t.Errorf("%s: declared to need credentials but answered %d with none", op.name, status)
		}

		if !bearer {
			// Session only: the most privileged key must still be refused.
			if status := f.call(t, op.name, f.keys["owner"], ""); !deniedStatus(status) {
				t.Errorf("%s: declared session-only but answered %d to an owner API key", op.name, status)
			}
		}

		if siteAdminOnly {
			if status := f.call(t, op.name, "", f.session); !deniedStatus(status) {
				t.Errorf("%s: declared site-admin but answered %d to an org owner's session", op.name, status)
			}
			if status := f.call(t, op.name, "", f.siteAdmin); deniedStatus(status) {
				t.Errorf("%s: declared site-admin but refused a site admin's session with %d", op.name, status)
			}
			continue
		}

		if cookie {
			if status := f.call(t, op.name, "", f.session); deniedStatus(status) {
				t.Errorf("%s: declares cookieAuth but refused an owner's session with %d", op.name, status)
			}
		}
		if bearer {
			atRole := op.minRole
			if atRole == "" {
				atRole = "viewer"
			}
			if status := f.call(t, op.name, f.keys[atRole], ""); deniedStatus(status) {
				t.Errorf("%s: declares min role %q but refused a %s key with %d", op.name, op.minRole, atRole, status)
			}
			if below := lowerRole(op.minRole); below != "" {
				if status := f.call(t, op.name, f.keys[below], ""); status != http.StatusForbidden {
					t.Errorf("%s: declares min role %q but answered %d to a %s key", op.name, op.minRole, status, below)
				}
			}
		}
	}
}

// TestOpenAPISecurity_TableCoversEveryOperation fails on a new operation with no
// access entry, and on an entry whose operation no longer exists.
func TestOpenAPISecurity_TableCoversEveryOperation(t *testing.T) {
	t.Parallel()
	documented := map[string]bool{}
	for _, op := range declaredOperations(t, newOpenAPITestHandler(t)) {
		documented[op.name] = true
	}
	for name := range operationAccess {
		if !documented[name] {
			t.Errorf("operationAccess has %q, which is not in the spec", name)
		}
	}
	for name := range documented {
		if _, ok := operationAccess[name]; !ok {
			t.Errorf("%s has no operationAccess entry", name)
		}
	}
}

// TestOpenAPISecurity_SchemesDeclared verifies both served documents declare the
// schemes operations refer to, and no API key scheme in a query parameter.
func TestOpenAPISecurity_SchemesDeclared(t *testing.T) {
	t.Parallel()
	handler := newOpenAPITestHandler(t)
	for _, doc := range []string{"/api/v1/openapi.json", "/api/v1/openapi-3.0.json"} {
		t.Run(doc, func(t *testing.T) {
			t.Parallel()
			spec := fetchSpec(t, handler, doc)
			schemes := spec["components"].(map[string]any)["securitySchemes"].(map[string]any)

			bearer := schemes["bearerAuth"].(map[string]any)
			if bearer["type"] != "http" || bearer["scheme"] != "bearer" {
				t.Errorf("bearerAuth = %v, want http bearer", bearer)
			}
			cookie := schemes["cookieAuth"].(map[string]any)
			if cookie["type"] != "apiKey" || cookie["in"] != "cookie" || cookie["name"] != "access_token" {
				t.Errorf("cookieAuth = %v, want the access_token cookie", cookie)
			}
			for name, raw := range schemes {
				if raw.(map[string]any)["in"] == "query" {
					t.Errorf("%s accepts a credential in a query parameter", name)
				}
			}

			list := spec["paths"].(map[string]any)["/orgs/{org_id}/watchlists"].(map[string]any)["get"].(map[string]any)
			got, err := json.Marshal(list["security"])
			if err != nil {
				t.Fatalf("marshal security: %v", err)
			}
			// OpenAPI 3.0 requires an empty list for these schemes; the role is in x-min-role.
			if string(got) != `[{"bearerAuth":[]},{"cookieAuth":[]}]` {
				t.Errorf("list-watchlists security = %s", got)
			}
			if list["x-min-role"] != "viewer" {
				t.Errorf("list-watchlists x-min-role = %v, want viewer", list["x-min-role"])
			}
		})
	}
}
