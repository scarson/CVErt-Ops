// ABOUTME: Integration tests for SSO connection CRUD handlers.
// ABOUTME: Tests enterprise tier gating, owner-only RBAC, secret encryption/masking, and domain management.
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
