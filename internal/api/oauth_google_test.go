// ABOUTME: Integration tests for the Google OIDC login flow.
// ABOUTME: Uses a mock OIDC server with RSA-signed ID tokens (no go-jose dependency).
package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// googleMockServer simulates Google's OIDC discovery, JWKS, and token endpoints.
type googleMockServer struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	mu         sync.Mutex
	nextNonce  string // set by test before calling callback
}

func (m *googleMockServer) setNonce(nonce string) {
	m.mu.Lock()
	m.nextNonce = nonce
	m.mu.Unlock()
}

func (m *googleMockServer) getNonce() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextNonce
}

// newGoogleMockServer creates a mock OIDC server using stdlib RSA + golang-jwt for ID token signing.
func newGoogleMockServer(t *testing.T) *googleMockServer {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	mock := &googleMockServer{privateKey: privateKey}
	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		baseURL := "http://" + r.Host
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"issuer":                                baseURL,
				"authorization_endpoint":                baseURL + "/auth",
				"token_endpoint":                        baseURL + "/token",
				"jwks_uri":                              baseURL + "/jwks",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/jwks":
			pub := &mock.privateKey.PublicKey
			n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"keys": []map[string]any{
					{"kty": "RSA", "kid": "test-key-1", "use": "sig", "alg": "RS256", "n": n, "e": e},
				},
			})
		case "/token":
			nonce := mock.getNonce()
			baseURLLocal := "http://" + r.Host
			claims := jwt.MapClaims{
				"iss":            baseURLLocal,
				"sub":            "google-sub-12345",
				"email":          "guser@example.com",
				"email_verified": true,
				"aud":            jwt.ClaimStrings{"test-google-client-id"},
				"exp":            jwt.NewNumericDate(time.Now().Add(time.Hour)),
				"iat":            jwt.NewNumericDate(time.Now()),
				"nonce":          nonce,
			}
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			tok.Header["kid"] = "test-key-1"
			idTokenStr, err := tok.SignedString(mock.privateKey)
			if err != nil {
				http.Error(w, "sign id token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:gosec // G104: test mock server
				"access_token": "goog_test_access_token",
				"token_type":   "bearer",
				"id_token":     idTokenStr,
				"expires_in":   3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(mock.server.Close)
	return mock
}

// newGoogleTestServer creates an API server with Google OIDC configured against the mock.
func newGoogleTestServer(t *testing.T, db *testutil.TestDB, googleMock *googleMockServer) (*Server, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:           "ggtest-secret-32-bytes-minimum-aa",
		Argon2MaxConcurrent: 5,
		ExternalURL:         "http://localhost",
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	// Create a real oidc.Provider pointing to the mock server (no real Google call).
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, googleMock.server.URL)
	if err != nil {
		t.Fatalf("oidc.NewProvider (mock): %v", err)
	}
	srv.googleOIDC = provider
	srv.googleOAuth = &oauth2.Config{
		ClientID:     "test-google-client-id",
		ClientSecret: "test-google-secret",
		RedirectURL:  "http://localhost/api/v1/auth/oauth/google/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

func TestGoogleInit_NotConfigured(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	cfg := &config.Config{ //nolint:exhaustruct,gosec // test: only relevant fields set; G101 false positive
		JWTSecret:           "ggtest-secret-32-bytes-minimum-aa",
		Argon2MaxConcurrent: 5,
	}
	srv, err := NewServer(db.Store, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	client := ts.Client()
	client.CheckRedirect = noRedirect
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/google", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("GET /auth/oauth/google: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", resp.StatusCode)
	}
}

func TestGoogleInit_Configured(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	googleMock := newGoogleMockServer(t)
	_, ts := newGoogleTestServer(t, db, googleMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/google", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("GET /auth/oauth/google: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("expected Location header")
	}
	var stateCookie, nonceCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected oauth_state cookie, not found")
	}
	if !stateCookie.HttpOnly {
		t.Error("oauth_state cookie must be HttpOnly")
	}
	if nonceCookie == nil {
		t.Fatal("expected oidc_nonce cookie, not found")
	}
	if !nonceCookie.HttpOnly {
		t.Error("oidc_nonce cookie must be HttpOnly")
	}
}

func TestGoogleCallback_NewUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	googleMock := newGoogleMockServer(t)
	_, ts := newGoogleTestServer(t, db, googleMock)

	// Step 1: Init to capture state + nonce cookies.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/google", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

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
		t.Fatal("no oauth_state cookie from init")
	}
	if nonceCookie == nil {
		t.Fatal("no oidc_nonce cookie from init")
	}

	// Step 2: Tell mock server what nonce to embed in the ID token.
	googleMock.setNonce(nonceCookie.Value)

	// Step 3: Call callback with state + nonce cookies.
	callbackURL := ts.URL + "/api/v1/auth/oauth/google/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	req.AddCookie(nonceCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Verify auth cookies are set.
	var accessCookie, refreshCookie *http.Cookie
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "access_token":
			accessCookie = c
		case "refresh_token":
			refreshCookie = c
		}
	}
	if accessCookie == nil {
		t.Error("expected access_token cookie")
	}
	if refreshCookie == nil {
		t.Error("expected refresh_token cookie")
	}

	// Verify user was created with Google sub.
	user, err := db.GetUserByProviderID(t.Context(), "google", "google-sub-12345")
	if err != nil {
		t.Fatalf("GetUserByProviderID: %v", err)
	}
	if user == nil {
		t.Fatal("expected user to be created")
	}
	if user.Email != "guser@example.com" {
		t.Errorf("user.Email = %q, want %q", user.Email, "guser@example.com")
	}
}

func TestGoogleCallback_ExistingUser(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	googleMock := newGoogleMockServer(t)
	_, ts := newGoogleTestServer(t, db, googleMock)

	// Pre-create user linked to Google sub.
	ctx := t.Context()
	existingUser, err := db.CreateUser(ctx, "old@example.com", "Old Name", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpsertUserIdentity(ctx, existingUser.ID, "google", "google-sub-12345", "old@example.com"); err != nil {
		t.Fatalf("UpsertUserIdentity: %v", err)
	}

	client := ts.Client()
	client.CheckRedirect = noRedirect

	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/google", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie, nonceCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}

	googleMock.setNonce(nonceCookie.Value)

	callbackURL := ts.URL + "/api/v1/auth/oauth/google/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	req.AddCookie(nonceCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Verify the same user ID is returned (not a new user).
	var body struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.UserID != existingUser.ID.String() {
		t.Errorf("user_id = %q, want %q", body.UserID, existingUser.ID.String())
	}
}

func TestGoogleCallback_InvalidState(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	googleMock := newGoogleMockServer(t)
	_, ts := newGoogleTestServer(t, db, googleMock)

	client := ts.Client()
	client.CheckRedirect = noRedirect

	// Call callback without a state cookie — missing cookie = invalid state.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		ts.URL+"/api/v1/auth/oauth/google/callback?code=fake-code&state=wrong-state", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestGoogleCallback_NonceMismatch(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	googleMock := newGoogleMockServer(t)
	_, ts := newGoogleTestServer(t, db, googleMock)

	// Init to get valid state + nonce cookies.
	client := ts.Client()
	client.CheckRedirect = noRedirect
	initReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, ts.URL+"/api/v1/auth/oauth/google", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	initResp, err := client.Do(initReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer initResp.Body.Close() //nolint:errcheck

	var stateCookie, nonceCookie *http.Cookie
	for _, c := range initResp.Cookies() {
		switch c.Name {
		case "oauth_state":
			stateCookie = c
		case "oidc_nonce":
			nonceCookie = c
		}
	}

	// Mock returns ID token with a DIFFERENT nonce than what's in the cookie.
	googleMock.setNonce("tampered-nonce-value")

	callbackURL := ts.URL + "/api/v1/auth/oauth/google/callback?code=fake-code&state=" + stateCookie.Value
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, callbackURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(stateCookie)
	req.AddCookie(nonceCookie)
	resp, err := client.Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
