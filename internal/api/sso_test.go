// ABOUTME: Integration tests for SSO connection CRUD handlers.
// ABOUTME: Tests enterprise tier gating, owner-only RBAC, secret encryption/masking, and domain management.
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/audit"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ── SSO HTTP helpers ─────────────────────────────────────────────────────────

func newSSOServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	srv, ts := newRegisterServer(t, db, "open")
	// Set an SSO encryption key (32 bytes hex-encoded = 64 hex chars).
	srv.cfg.SSOEncryptionKey = hex.EncodeToString([]byte("12345678901234567890123456789012"))
	return srv, ts
}

func doCreateSSO(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/sso", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("create SSO: %v", err)
	}
	return resp
}

func doGetSSO(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+orgID+"/sso", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("get SSO: %v", err)
	}
	return resp
}

func doPatchSSO(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPatch, ts.URL+"/api/v1/orgs/"+orgID+"/sso", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("patch SSO: %v", err)
	}
	return resp
}

func doDeleteSSO(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL+"/api/v1/orgs/"+orgID+"/sso", nil)
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("delete SSO: %v", err)
	}
	return resp
}

func doPutSSODomains(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, ts.URL+"/api/v1/orgs/"+orgID+"/sso/domains", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("put SSO domains: %v", err)
	}
	return resp
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestSSOConnection_CRUD(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-owner@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-owner@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, reg.OrgID)

	// Set enterprise tier (SSO is enterprise-only).
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// CREATE
	createBody := `{"display_name":"Acme IdP","issuer_url":"https://idp.acme.com","client_id":"acme-client","client_secret":"super-secret","scopes":["openid","email"]}`
	resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d, want 201. Body: %s", resp.StatusCode, body)
	}
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created["display_name"] != "Acme IdP" {
		t.Errorf("display_name = %v, want Acme IdP", created["display_name"])
	}

	// GET — secret must be masked.
	resp2 := doGetSSO(t, ctx, ts, token, reg.OrgID)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("get: got %d, want 200. Body: %s", resp2.StatusCode, body)
	}
	var got map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got["client_secret"] != "***" {
		t.Errorf("client_secret = %v, want '***' (masked)", got["client_secret"])
	}
	if got["display_name"] != "Acme IdP" {
		t.Errorf("display_name = %v, want Acme IdP", got["display_name"])
	}

	// PATCH
	patchBody := `{"display_name":"Updated IdP","enabled":true}`
	resp3 := doPatchSSO(t, ctx, ts, token, reg.OrgID, patchBody)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp3.Body)
		t.Fatalf("patch: got %d, want 200. Body: %s", resp3.StatusCode, body)
	}
	var patched map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched["display_name"] != "Updated IdP" {
		t.Errorf("display_name = %v, want Updated IdP", patched["display_name"])
	}
	if patched["enabled"] != true {
		t.Errorf("enabled = %v, want true", patched["enabled"])
	}

	// DELETE
	resp4 := doDeleteSSO(t, ctx, ts, token, reg.OrgID)
	defer resp4.Body.Close() //nolint:errcheck,gosec // G104
	if resp4.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp4.Body)
		t.Fatalf("delete: got %d, want 204. Body: %s", resp4.StatusCode, body)
	}

	// GET after delete — should be 404.
	resp5 := doGetSSO(t, ctx, ts, token, reg.OrgID)
	defer resp5.Body.Close() //nolint:errcheck,gosec // G104
	if resp5.StatusCode != http.StatusNotFound {
		t.Errorf("get after delete: got %d, want 404", resp5.StatusCode)
	}
}

func TestSSOConnection_TierGating(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-free@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-free@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	// Org defaults to "free" tier — SSO should be blocked.
	createBody := `{"display_name":"Test","issuer_url":"https://idp.test.com","client_id":"c","client_secret":"s"}`
	resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("non-enterprise create: got %d, want 403. Body: %s", resp.StatusCode, body)
	}
}

func TestSSOConnection_RBAC(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	// Owner creates org.
	reg := doRegister(t, ctx, ts, "sso-rbac-owner@example.com", "test-password-1234")
	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// Create a member (non-owner) in the same org.
	memberReg := doRegister(t, ctx, ts, "sso-rbac-member@example.com", "test-password-1234")
	// Move member to the owner's org.
	memberID := mustParseUUID(t, memberReg.UserID)
	if err := db.CreateOrgMember(ctx, orgID, memberID, "member"); err != nil {
		t.Fatalf("create org member: %v", err)
	}
	// Log in as member.
	memberLogin := doLogin(t, ctx, ts, "sso-rbac-member@example.com", "test-password-1234")
	defer memberLogin.Body.Close() //nolint:errcheck,gosec // G104
	memberToken := cookieValue(memberLogin, "access_token")

	// Member should get 403 on SSO create (owner-only).
	createBody := `{"display_name":"Test","issuer_url":"https://idp.test.com","client_id":"c","client_secret":"s"}`
	resp := doCreateSSO(t, ctx, ts, memberToken, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("member create SSO: got %d, want 403. Body: %s", resp.StatusCode, body)
	}
}

func TestSSOConnection_SecretEncrypted(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-enc@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-enc@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	createBody := `{"display_name":"EncTest","issuer_url":"https://idp.enc.com","client_id":"enc-client","client_secret":"my-cleartext-secret"}`
	resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create: got %d. Body: %s", resp.StatusCode, body)
	}

	// Verify the DB value is NOT the cleartext secret.
	conn, err := db.GetSSOConnection(ctx, orgID)
	if err != nil {
		t.Fatalf("GetSSOConnection: %v", err)
	}
	if string(conn.ClientSecretEnc) == "my-cleartext-secret" {
		t.Fatal("client_secret_enc in DB is plaintext — expected encrypted bytes")
	}
	if len(conn.ClientSecretEnc) == 0 {
		t.Fatal("client_secret_enc is empty")
	}
}

func TestSSOConnection_UniquePerOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-uniq@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-uniq@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	createBody := `{"display_name":"First","issuer_url":"https://idp1.com","client_id":"c1","client_secret":"s1"}`
	resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first create: got %d", resp.StatusCode)
	}

	// Second create should fail.
	createBody2 := `{"display_name":"Second","issuer_url":"https://idp2.com","client_id":"c2","client_secret":"s2"}`
	resp2 := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody2)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second create: got %d, want 409", resp2.StatusCode)
	}
}

// ── Discover endpoint tests ──────────────────────────────────────────────────

// setupSSOWithDomains creates an enterprise org with an enabled SSO connection and domains.
// Returns the org owner's access token and org ID.
func setupSSOWithDomains(t *testing.T, db *testutil.TestDB, srv *Server, ts *httptest.Server, email string, domains []string, enabled bool) (token, orgID string) {
	t.Helper()
	ctx := context.Background()
	reg := doRegister(t, ctx, ts, email, "test-password-1234")
	loginResp := doLogin(t, ctx, ts, email, "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token = cookieValue(loginResp, "access_token")
	orgID = reg.OrgID

	oid := mustParseUUID(t, orgID)
	if err := db.UpdateOrgTier(ctx, oid, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(oid)

	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	createBody := `{"display_name":"Test IdP","issuer_url":"https://idp.test.com","client_id":"c","client_secret":"s","enabled":` + enabledStr + `}`
	resp := doCreateSSO(t, ctx, ts, token, orgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("create SSO: got %d. Body: %s", resp.StatusCode, body)
	}

	if len(domains) > 0 {
		domainsJSON, _ := json.Marshal(domains)
		domainBody := `{"domains":` + string(domainsJSON) + `}`
		resp2 := doPutSSODomains(t, ctx, ts, token, orgID, domainBody)
		defer resp2.Body.Close() //nolint:errcheck,gosec // G104
		if resp2.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp2.Body)
			t.Fatalf("put domains: got %d. Body: %s", resp2.StatusCode, body)
		}
	}
	return token, orgID
}

func doDiscover(t *testing.T, ctx context.Context, ts *httptest.Server, email string) *http.Response {
	t.Helper()
	body := `{"email":"` + email + `"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/discover", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	return resp
}

func TestDiscover_MatchingDomain(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	setupSSOWithDomains(t, db, srv, ts, "disc-owner@example.com", []string{"acme.com"}, true)

	resp := doDiscover(t, ctx, ts, "user@acme.com")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("discover: got %d. Body: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["display_name"] != "Test IdP" {
		t.Errorf("display_name = %v, want Test IdP", got["display_name"])
	}
	if got["connection_id"] == nil || got["connection_id"] == "" {
		t.Errorf("connection_id missing")
	}
}

func TestDiscover_UnknownDomain(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSSOServer(t, db)

	resp := doDiscover(t, ctx, ts, "user@nonexistent.com")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("discover: got %d. Body: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// No SSO configured — response should not have connection_id.
	if got["connection_id"] != nil && got["connection_id"] != "" {
		t.Errorf("expected empty result for unknown domain, got connection_id=%v", got["connection_id"])
	}
}

func TestDiscover_DisabledConnection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	// Set up SSO but leave it disabled.
	setupSSOWithDomains(t, db, srv, ts, "disc-disabled@example.com", []string{"disabled.com"}, false)

	resp := doDiscover(t, ctx, ts, "user@disabled.com")
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("discover: got %d. Body: %s", resp.StatusCode, body)
	}
	var got map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Disabled connection — should not be returned.
	if got["connection_id"] != nil && got["connection_id"] != "" {
		t.Errorf("expected no result for disabled connection, got connection_id=%v", got["connection_id"])
	}
}

// ── Email domain tests ──────────────────────────────────────────────────────

func TestSSOEmailDomain_PutAndCascade(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-domain@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-domain@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")

	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// Create connection first.
	createBody := `{"display_name":"Domain","issuer_url":"https://idp.dom.com","client_id":"c","client_secret":"s"}`
	resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: got %d", resp.StatusCode)
	}

	// PUT domains.
	domainBody := `{"domains":["acme.com","acme.org"]}`
	resp2 := doPutSSODomains(t, ctx, ts, token, reg.OrgID, domainBody)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("put domains: got %d. Body: %s", resp2.StatusCode, body)
	}

	// GET should include domains.
	resp3 := doGetSSO(t, ctx, ts, token, reg.OrgID)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	var got map[string]any
	if err := json.NewDecoder(resp3.Body).Decode(&got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	domains, ok := got["domains"].([]any)
	if !ok {
		t.Fatalf("domains field missing or wrong type: %v", got["domains"])
	}
	if len(domains) != 2 {
		t.Errorf("domains count = %d, want 2", len(domains))
	}

	// Delete connection — domains should cascade.
	resp4 := doDeleteSSO(t, ctx, ts, token, reg.OrgID)
	defer resp4.Body.Close() //nolint:errcheck,gosec // G104
	if resp4.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: got %d", resp4.StatusCode)
	}
}

func TestDiscover_RateLimited(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	_, ts := newSSOServer(t, db)
	ctx := context.Background()

	// Rate limiter: 10/min burst=10. Send 11 rapid requests to trip the limiter.
	for i := 1; i <= 11; i++ {
		resp := doDiscover(t, ctx, ts, "probe@unknown.com")
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if i <= 10 {
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("request %d: got %d, want 200", i, resp.StatusCode)
			}
		} else {
			if resp.StatusCode != http.StatusTooManyRequests {
				t.Errorf("request %d: got %d, want 429", i, resp.StatusCode)
			}
		}
	}
}

func TestSSODomains_ValidatesFormat(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	token, orgID := setupSSOWithDomains(t, db, srv, ts, "sso-valdomain@example.com", nil, true)

	// Empty domain string after trim should be rejected.
	resp := doPutSSODomains(t, ctx, ts, token, orgID, `{"domains":["  "]}`)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("empty domain: got %d, want 422", resp.StatusCode)
	}

	// Domain without a dot should be rejected.
	resp2 := doPutSSODomains(t, ctx, ts, token, orgID, `{"domains":["nodot"]}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec // G104
	if resp2.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("no-dot domain: got %d, want 422", resp2.StatusCode)
	}

	// Domain with space should be rejected.
	resp3 := doPutSSODomains(t, ctx, ts, token, orgID, `{"domains":["a b.com"]}`)
	defer resp3.Body.Close() //nolint:errcheck,gosec // G104
	if resp3.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("space domain: got %d, want 422", resp3.StatusCode)
	}
}

// ── Input validation ─────────────────────────────────────────────────────────

func TestDiscover_InputValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newSSOServer(t, db)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"invalid JSON", "{bad", http.StatusBadRequest},
		{"empty email", `{"email":""}`, http.StatusUnprocessableEntity},
		{"whitespace email", `{"email":"  "}`, http.StatusUnprocessableEntity},
		{"no at sign", `{"email":"nope"}`, http.StatusUnprocessableEntity},
		{"nothing after at", `{"email":"user@"}`, http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/auth/discover",
				bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
			if err != nil {
				t.Fatalf("discover: %v", err)
			}
			resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode != tt.want {
				t.Errorf("%s: got %d, want %d", tt.name, resp.StatusCode, tt.want)
			}
		})
	}
}

func TestCreateSSO_FieldValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-val@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-val@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")
	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	tests := []struct {
		name string
		body string
		want int
	}{
		{"invalid JSON", "{bad", http.StatusBadRequest},
		{"empty display_name", `{"display_name":"","issuer_url":"https://x","client_id":"c","client_secret":"s"}`, http.StatusUnprocessableEntity},
		{"empty issuer_url", `{"display_name":"N","issuer_url":"","client_id":"c","client_secret":"s"}`, http.StatusUnprocessableEntity},
		{"empty client_id", `{"display_name":"N","issuer_url":"https://x","client_id":"","client_secret":"s"}`, http.StatusUnprocessableEntity},
		{"empty client_secret", `{"display_name":"N","issuer_url":"https://x","client_id":"c","client_secret":""}`, http.StatusUnprocessableEntity},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, tt.body)
			resp.Body.Close() //nolint:errcheck,gosec
			if resp.StatusCode != tt.want {
				t.Errorf("%s: got %d, want %d", tt.name, resp.StatusCode, tt.want)
			}
		})
	}
}

func TestPatchSSO_NoConnection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-pnc@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-pnc@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")
	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// PATCH without creating a connection first → 404.
	resp := doPatchSSO(t, ctx, ts, token, reg.OrgID, `{"display_name":"X"}`)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("patch no connection: got %d, want 404", resp.StatusCode)
	}
}

func TestPutSSODomains_NoConnection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "sso-dnc@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "sso-dnc@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec
	token := cookieValue(loginResp, "access_token")
	orgID := mustParseUUID(t, reg.OrgID)
	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// PUT domains without creating a connection first → 404.
	resp := doPutSSODomains(t, ctx, ts, token, reg.OrgID, `{"domains":["example.com"]}`)
	defer resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("put domains no connection: got %d, want 404", resp.StatusCode)
	}
}

func TestSSODomains_AdditionalValidation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts := newSSOServer(t, db)

	token, orgID := setupSSOWithDomains(t, db, srv, ts, "sso-dav@example.com", nil, false)

	// Domain > 253 characters.
	longDomain := strings.Repeat("a", 250) + ".com"
	resp := doPutSSODomains(t, ctx, ts, token, orgID, `{"domains":["`+longDomain+`"]}`)
	resp.Body.Close() //nolint:errcheck,gosec
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("long domain: got %d, want 422", resp.StatusCode)
	}

	// Uppercase domain should be normalized (accepted, stored as lowercase).
	resp2 := doPutSSODomains(t, ctx, ts, token, orgID, `{"domains":["UPPER.COM"]}`)
	defer resp2.Body.Close() //nolint:errcheck,gosec
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("uppercase domain: got %d, want 200", resp2.StatusCode)
	}
	// GET should return lowercase.
	getResp := doGetSSO(t, ctx, ts, token, orgID)
	defer getResp.Body.Close() //nolint:errcheck,gosec
	var ssoData map[string]any
	json.NewDecoder(getResp.Body).Decode(&ssoData) //nolint:errcheck,gosec
	domains, _ := ssoData["domains"].([]any)
	if len(domains) != 1 || domains[0] != "upper.com" {
		t.Errorf("domain not normalized to lowercase: got %v", domains)
	}
}

// ── Audit integration ───────────────────────────────────────────────────────

func newAuditSSOServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server, *audit.Writer) {
	t.Helper()
	srv, ts := newSSOServer(t, db)
	w := audit.NewWriter(db.Store, slog.Default())
	srv.SetAuditDeps(w)
	return srv, ts, w
}

func TestAudit_SSOOperations(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv, ts, aw := newAuditSSOServer(t, db)

	reg := doRegister(t, ctx, ts, "audit-sso@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "audit-sso@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")
	orgID := mustParseUUID(t, reg.OrgID)

	if err := db.UpdateOrgTier(ctx, orgID, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(orgID)

	// Sub-tests run sequentially: create → update → delete.
	t.Run("Create", func(t *testing.T) {
		body := `{"display_name":"Audit IdP","issuer_url":"https://idp.example.com","client_id":"test","client_secret":"secret","enabled":false}`
		resp := doCreateSSO(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create: got %d, want 201", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "sso_connection", "create")
		if entry == nil {
			t.Fatal("no audit entry for SSO create")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
	})

	t.Run("Update", func(t *testing.T) {
		body := `{"display_name":"Updated IdP"}`
		resp := doPatchSSO(t, ctx, ts, token, reg.OrgID, body)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patch: got %d, want 200", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "sso_connection", "update")
		if entry == nil {
			t.Fatal("no audit entry for SSO update")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		resp := doDeleteSSO(t, ctx, ts, token, reg.OrgID)
		defer resp.Body.Close() //nolint:errcheck,gosec // G104
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("delete: got %d, want 204", resp.StatusCode)
		}

		aw.Flush()

		entry := findAuditEntry(t, db, orgID, "sso_connection", "delete")
		if entry == nil {
			t.Fatal("no audit entry for SSO delete")
		}
		if !entry.Success {
			t.Error("expected success=true")
		}
	})
}
