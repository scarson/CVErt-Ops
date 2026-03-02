// ABOUTME: Integration tests for the generic OIDC SSO login flow.
// ABOUTME: Uses a mock OIDC IdP with RSA-signed ID tokens to test init, callback, and error paths.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newOIDCTestServer creates a server wired for OIDC SSO testing.
func newOIDCTestServer(t *testing.T, db *testutil.TestDB) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set
		JWTSecret:           "oidc-test-secret-32-bytes-aaaaaaa",
		Argon2MaxConcurrent: 5,
		ExternalURL:         "http://localhost",
		RegistrationMode:    "open",
		SSOEncryptionKey:    hex.EncodeToString([]byte("12345678901234567890123456789012")),
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// setupOIDCConnection creates an org with enterprise tier, an SSO connection pointing
// at the mock IdP, and sets email domains. Returns orgID and connectionID.
func setupOIDCConnection(t *testing.T, db *testutil.TestDB, srv *Server, ts *httptest.Server,
	mock *testutil.MockOIDC, email string, domains []string, enabled bool,
) (orgID, connectionID string) {
	t.Helper()
	ctx := context.Background()
	reg := doRegister(t, ctx, ts, email, "test-password-1234")
	loginResp := doLogin(t, ctx, ts, email, "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	token := cookieValue(loginResp, "access_token")
	orgID = reg.OrgID

	// BootstrapFirstUserOrg only creates an org for the first user on the server.
	// Subsequent users need an org created explicitly.
	if orgID == "" {
		userID := mustParseUUID(t, reg.UserID)
		org, err := db.CreateOrg(ctx, email+"'s Org")
		if err != nil {
			t.Fatalf("create org: %v", err)
		}
		if err := db.CreateOrgMember(ctx, org.ID, userID, "owner"); err != nil {
			t.Fatalf("create org member: %v", err)
		}
		orgID = org.ID.String()
		// Re-login to get token with org membership.
		loginResp2 := doLogin(t, ctx, ts, email, "test-password-1234")
		defer loginResp2.Body.Close() //nolint:errcheck,gosec // G104
		token = cookieValue(loginResp2, "access_token")
	}

	oid := mustParseUUID(t, orgID)
	if err := db.UpdateOrgTier(ctx, oid, "enterprise"); err != nil {
		t.Fatalf("update tier: %v", err)
	}
	srv.tierCache.Invalidate(oid)

	enabledStr := "false"
	if enabled {
		enabledStr = "true"
	}
	createBody := `{"display_name":"Mock IdP","issuer_url":"` + mock.Server.URL + `","client_id":"` + mock.ClientID + `","client_secret":"mock-secret","enabled":` + enabledStr + `}`
	resp := doCreateSSO(t, ctx, ts, token, orgID, createBody)
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create SSO: got %d", resp.StatusCode)
	}
	var created map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	connectionID = created["id"].(string)

	if len(domains) > 0 {
		domainsJSON, _ := json.Marshal(domains)
		domBody := `{"domains":` + string(domainsJSON) + `}`
		resp2 := doPutSSODomains(t, ctx, ts, token, orgID, domBody)
		defer resp2.Body.Close() //nolint:errcheck,gosec // G104
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("put domains: got %d", resp2.StatusCode)
		}
	}
	return orgID, connectionID
}

func TestOIDCFlow_Success(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	mock := testutil.NewMockOIDC(t)
	srv, ts := newOIDCTestServer(t, db)

	_, connID := setupOIDCConnection(t, db, srv, ts, mock, "oidc-owner@example.com", []string{"corp.com"}, true)

	// Pre-create a user with linked SSO identity.
	user, err := db.CreateUser(ctx, "alice@corp.com", "Alice", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	providerKey := "oidc:" + connID
	if err := db.UpsertUserIdentity(ctx, user.ID, providerKey, mock.Sub, "alice@corp.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	// Step 1: Init — should redirect to IdP.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/oidc/"+connID+"/login", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck,gosec // G104
	if initResp.StatusCode != http.StatusFound {
		t.Fatalf("init: got %d, want 302", initResp.StatusCode)
	}

	// Extract state and nonce cookies.
	var stateCookie, nonceCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("missing oauth_state cookie")
	}
	if nonceCookie == nil {
		t.Fatal("missing oidc_nonce cookie")
	}

	// Verify redirect URL points to mock IdP.
	loc := initResp.Header.Get("Location")
	locURL, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if locURL.Host != mock.Server.Listener.Addr().String() {
		t.Errorf("redirect host = %s, want mock IdP", locURL.Host)
	}

	// Step 2: Tell mock what nonce to put in the ID token.
	mock.SetNonce(nonceCookie.Value)

	// Step 3: Call callback with code + state + cookies.
	// State encodes connection_id — extract it from the redirect state param.
	callbackURL := ts.URL + "/api/v1/auth/oidc/callback?code=mock-code&state=" + stateCookie.Value
	cbReq, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	cbReq.AddCookie(stateCookie)
	cbReq.AddCookie(nonceCookie)
	cbResp, err := client.Do(cbReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer cbResp.Body.Close() //nolint:errcheck,gosec // G104
	if cbResp.StatusCode != http.StatusOK {
		var body json.RawMessage
		json.NewDecoder(cbResp.Body).Decode(&body) //nolint:errcheck,gosec // diagnostic
		t.Fatalf("callback: got %d, want 200. Body: %s", cbResp.StatusCode, body)
	}

	// Verify JWT cookies are set.
	var accessCookie *http.Cookie
	for _, c := range cbResp.Cookies() {
		if c.Name == "access_token" {
			accessCookie = c
		}
	}
	if accessCookie == nil {
		t.Error("expected access_token cookie")
	}

	// Verify correct user ID in response.
	var body map[string]string
	if err := json.NewDecoder(cbResp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["user_id"] != user.ID.String() {
		t.Errorf("user_id = %q, want %q", body["user_id"], user.ID.String())
	}
}

func TestOIDCFlow_NoIdentity(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	mock := testutil.NewMockOIDC(t)
	srv, ts := newOIDCTestServer(t, db)

	_, connID := setupOIDCConnection(t, db, srv, ts, mock, "oidc-nolink@example.com", []string{"nolink.com"}, true)

	// No user identity linked — callback should fail.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/oidc/"+connID+"/login", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck,gosec // G104

	if initResp.StatusCode != http.StatusFound {
		t.Fatalf("init: got %d, want 302", initResp.StatusCode)
	}

	var stateCookie, nonceCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("missing oauth_state cookie")
	}
	if nonceCookie == nil {
		t.Fatal("missing oidc_nonce cookie")
	}
	mock.SetNonce(nonceCookie.Value)

	callbackURL := ts.URL + "/api/v1/auth/oidc/callback?code=mock-code&state=" + stateCookie.Value
	cbReq, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	cbReq.AddCookie(stateCookie)
	cbReq.AddCookie(nonceCookie)
	cbResp, err := client.Do(cbReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer cbResp.Body.Close() //nolint:errcheck,gosec // G104

	// No linked identity → should return 403 with helpful message.
	if cbResp.StatusCode != http.StatusForbidden {
		t.Errorf("callback: got %d, want 403 (no linked identity)", cbResp.StatusCode)
	}
}

func TestOIDCFlow_CSRFMismatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	mock := testutil.NewMockOIDC(t)
	srv, ts := newOIDCTestServer(t, db)

	_, connID := setupOIDCConnection(t, db, srv, ts, mock, "oidc-csrf@example.com", nil, true)

	client := ts.Client()
	client.CheckRedirect = noRedirect

	// Call callback with a tampered state (no matching cookie).
	callbackURL := ts.URL + "/api/v1/auth/oidc/callback?code=mock-code&state=tampered_" + connID
	cbReq, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	cbResp, err := client.Do(cbReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer cbResp.Body.Close() //nolint:errcheck,gosec // G104
	if cbResp.StatusCode != http.StatusBadRequest {
		t.Errorf("callback: got %d, want 400 (CSRF mismatch)", cbResp.StatusCode)
	}
}

func TestOIDCFlow_DisabledConnection(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	mock := testutil.NewMockOIDC(t)
	srv, ts := newOIDCTestServer(t, db)

	// Create disabled connection.
	_, connID := setupOIDCConnection(t, db, srv, ts, mock, "oidc-disabled@example.com", nil, false)

	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/oidc/"+connID+"/login", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck,gosec // G104
	if initResp.StatusCode != http.StatusForbidden {
		t.Errorf("init disabled: got %d, want 403", initResp.StatusCode)
	}
}

func TestOIDCFlow_CrossOrgIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	mock := testutil.NewMockOIDC(t)
	srv, ts := newOIDCTestServer(t, db)

	// Create two orgs with SSO connections pointing at the same mock IdP.
	_, connID1 := setupOIDCConnection(t, db, srv, ts, mock, "cross-org1@example.com", nil, true)
	_, connID2 := setupOIDCConnection(t, db, srv, ts, mock, "cross-org2@example.com", nil, true)

	// Link identity to connection 1 only (same sub, same IdP).
	user, err := db.CreateUser(ctx, "cross-user@corp.com", "CrossUser", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	providerKey := "oidc:" + connID1
	if err := db.UpsertUserIdentity(ctx, user.ID, providerKey, mock.Sub, "cross-user@corp.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	// Attempt login via connection 2 (identity not linked there) → should 403.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/auth/oidc/"+connID2+"/login", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck,gosec // G104
	if initResp.StatusCode != http.StatusFound {
		t.Fatalf("init: got %d, want 302", initResp.StatusCode)
	}

	var stateCookie, nonceCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("missing oauth_state cookie")
	}
	if nonceCookie == nil {
		t.Fatal("missing oidc_nonce cookie")
	}
	mock.SetNonce(nonceCookie.Value)

	callbackURL := ts.URL + "/api/v1/auth/oidc/callback?code=mock-code&state=" + stateCookie.Value
	cbReq, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	cbReq.AddCookie(stateCookie)
	cbReq.AddCookie(nonceCookie)
	cbResp, err := client.Do(cbReq) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer cbResp.Body.Close() //nolint:errcheck,gosec // G104

	// Same sub, different connection → must get 403 (no linked identity for conn2).
	if cbResp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-org callback: got %d, want 403 (identity linked to conn1, not conn2)", cbResp.StatusCode)
	}
}
