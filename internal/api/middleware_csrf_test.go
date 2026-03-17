// ABOUTME: Integration tests for CSRF header middleware.
// ABOUTME: Verifies that cookie-authenticated state-changing requests require X-Requested-By.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// rawAPIKey creates an API key for the given org via cookie auth and returns the raw key.
func rawAPIKey(t *testing.T, ctx context.Context, ts *httptest.Server, accessToken, orgID string) string {
	t.Helper()
	body := `{"name":"csrf-test-key","role":"member"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs/"+orgID+"/api-keys", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", "access_token="+accessToken)
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api key: got %d, want 201", resp.StatusCode)
	}
	var out struct {
		RawKey string `json:"raw_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode api key response: %v", err)
	}
	if out.RawKey == "" {
		t.Fatal("api key response: empty raw_key")
	}
	return out.RawKey
}

// TestCSRF_BlocksCookiePostWithoutHeader verifies that a state-changing request
// authenticated via cookie is rejected with 403 when X-Requested-By is absent.
func TestCSRF_BlocksCookiePostWithoutHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "csrftest1@example.com", "supersecretpassword1!")
	loginResp := doLogin(t, ctx, ts, "csrftest1@example.com", "supersecretpassword1!")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token after login")
	}

	// POST without X-Requested-By — must be rejected with 403.
	body := `{"name":"NoCSRFOrg"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cookie POST without CSRF header: got %d, want 403", resp.StatusCode)
	}
}

// TestCSRF_AllowsCookiePostWithHeader verifies that a state-changing request
// authenticated via cookie succeeds when X-Requested-By: CVErt-Ops is present.
func TestCSRF_AllowsCookiePostWithHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	doRegister(t, ctx, ts, "csrftest2@example.com", "supersecretpassword2!")
	loginResp := doLogin(t, ctx, ts, "csrftest2@example.com", "supersecretpassword2!")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token after login")
	}

	// POST with X-Requested-By — must reach the handler (201 Created).
	body := `{"name":"CSRFOrg"}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-By", "CVErt-Ops")
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("cookie POST with CSRF header: got %d, want 201", resp.StatusCode)
	}
}

// TestCSRF_AllowsGETWithoutHeader verifies that safe methods (GET) bypass the
// CSRF check even when authenticated via cookie.
func TestCSRF_AllowsGETWithoutHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "csrftest3@example.com", "supersecretpassword3!")
	loginResp := doLogin(t, ctx, ts, "csrftest3@example.com", "supersecretpassword3!")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token after login")
	}

	// GET without X-Requested-By — must reach the handler (200 OK).
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/orgs/"+reg.OrgID, nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: accessToken})
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusOK {
		t.Errorf("cookie GET without CSRF header: got %d, want 200", resp.StatusCode)
	}
}

// TestCSRF_AllowsAPIKeyPostWithoutHeader verifies that API-key-authenticated
// state-changing requests bypass the CSRF check (no cookie = no CSRF risk).
func TestCSRF_AllowsAPIKeyPostWithoutHeader(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	_, ts := newRegisterServer(t, db, "open")

	reg := doRegister(t, ctx, ts, "csrftest4@example.com", "supersecretpassword4!")
	loginResp := doLogin(t, ctx, ts, "csrftest4@example.com", "supersecretpassword4!")
	defer loginResp.Body.Close() //nolint:errcheck,gosec // G104
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("no access_token after login")
	}

	// Create an API key (with CSRF header since using cookie) to get a raw key.
	key := rawAPIKey(t, ctx, ts, accessToken, reg.OrgID)

	// POST using API key Bearer token — no cookie and no X-Requested-By — must succeed.
	body := fmt.Sprintf(`{"name":"APIKeyOrg%s"}`, key[:8])
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/api/v1/orgs", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck,gosec // G104
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("API key POST without CSRF header: got %d, want 201", resp.StatusCode)
	}
}

// TestCSRF_SafeMethodsAllowed verifies that all safe HTTP methods bypass the
// CSRF check even when a cookie is present.
func TestCSRF_SafeMethodsAllowed(t *testing.T) {
	t.Parallel()
	safeMethods := []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodOptions,
		http.MethodTrace,
	}
	for _, method := range safeMethods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			handler := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(method, "/api/v1/test", nil)
			req.AddCookie(&http.Cookie{Name: "access_token", Value: "fake-token"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s with cookie: got %d, want 200", method, rec.Code)
			}
		})
	}
}

// TestCSRF_StateChangingMethodsBlocked verifies that all state-changing HTTP
// methods are blocked when a cookie is present without the CSRF header.
func TestCSRF_StateChangingMethodsBlocked(t *testing.T) {
	t.Parallel()
	unsafeMethods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}
	for _, method := range unsafeMethods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			handler := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(method, "/api/v1/test", nil)
			req.AddCookie(&http.Cookie{Name: "access_token", Value: "fake-token"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with cookie, no CSRF header: got %d, want 403", method, rec.Code)
			}
		})
	}
}

// TestCSRF_WrongHeaderValue verifies that the wrong X-Requested-By value is
// rejected — the check is an exact string match, not just presence.
func TestCSRF_WrongHeaderValue(t *testing.T) {
	t.Parallel()
	handler := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "fake-token"})
	req.Header.Set("X-Requested-By", "wrong-value")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST with wrong CSRF header value: got %d, want 403", rec.Code)
	}
}

// TestCSRF_ErrorFormat_RFC9457 verifies that the CSRF rejection response uses
// RFC 9457 Problem Details format (application/problem+json).
func TestCSRF_ErrorFormat_RFC9457(t *testing.T) {
	t.Parallel()
	handler := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/test", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "fake-token"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("CSRF rejection: got %d, want 403", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/problem+json")
	}
	var problem struct {
		Status int    `json:"status"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem+json: %v", err)
	}
	if problem.Status != http.StatusForbidden {
		t.Errorf("problem.status = %d, want %d", problem.Status, http.StatusForbidden)
	}
	if problem.Title == "" {
		t.Error("problem.title is empty")
	}
	if problem.Detail == "" {
		t.Error("problem.detail is empty")
	}
}

// TestCSRF_NoCookieBypassesCheck verifies that requests without an
// access_token cookie bypass the CSRF check for all state-changing methods.
func TestCSRF_NoCookieBypassesCheck(t *testing.T) {
	t.Parallel()
	unsafeMethods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}
	for _, method := range unsafeMethods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			handler := csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			req := httptest.NewRequest(method, "/api/v1/test", nil)
			// No cookie — should pass through without CSRF header.
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Errorf("%s without cookie: got %d, want 200", method, rec.Code)
			}
		})
	}
}
