// ABOUTME: Tests for the API key query parameter rejection middleware.
// ABOUTME: Verifies that sensitive parameters in URLs are blocked, and normal requests pass through.
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestRejectAPIKeyQueryParams_IntegrationWired verifies that the middleware is
// actually wired into the HTTP server's middleware chain (not just that the
// function itself works). Goes through the full HTTP stack via httptest.Server.
func TestRejectAPIKeyQueryParams_IntegrationWired(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	_, ts := newRegisterServer(t, db, "open")

	// Register and login to get an auth cookie.
	reg := doRegister(t, ctx, ts, "apikey-middleware@example.com", "test-password-1234")
	loginResp := doLogin(t, ctx, ts, "apikey-middleware@example.com", "test-password-1234")
	defer loginResp.Body.Close() //nolint:errcheck
	accessToken := cookieValue(loginResp, "access_token")
	if accessToken == "" {
		t.Fatal("login did not return access_token cookie")
	}
	_ = reg // org_id not needed for this test

	// Request WITH api_key query param — middleware should reject with 400.
	rejReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves?api_key=test", nil)
	rejReq.Header.Set("Cookie", "access_token="+accessToken)
	rejResp, err := ts.Client().Do(rejReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request with api_key param: %v", err)
	}
	defer rejResp.Body.Close() //nolint:errcheck
	if rejResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(rejResp.Body) //nolint:errcheck
		t.Fatalf("api_key param: got %d, want 400; body: %s", rejResp.StatusCode, body)
	}

	// Request WITHOUT api_key query param — should pass through to the handler.
	okReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/v1/cves", nil)
	okReq.Header.Set("Cookie", "access_token="+accessToken)
	okResp, err := ts.Client().Do(okReq) //nolint:gosec // G704 false positive: ts.URL is httptest.Server
	if err != nil {
		t.Fatalf("request without api_key param: %v", err)
	}
	defer okResp.Body.Close() //nolint:errcheck
	if okResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(okResp.Body) //nolint:errcheck
		t.Fatalf("no api_key param: got %d, want 200; body: %s", okResp.StatusCode, body)
	}
}

func TestRejectAPIKeyQueryParams_BlocksSensitiveParams(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	sensitiveNames := []string{
		"api_key", "apikey", "api-key", "token",
		"access_token", "key", "secret", "bearer",
	}

	for _, param := range sensitiveNames {
		t.Run(param, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/?"+param+"=some-secret-value", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("param %q: got %d, want 400", param, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Errorf("param %q: Content-Type = %q, want application/problem+json", param, ct)
			}
		})
	}
}

func TestRejectAPIKeyQueryParams_CaseInsensitive(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/?API_KEY=some-value", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("uppercase API_KEY: got %d, want 400", rec.Code)
	}
}

func TestRejectAPIKeyQueryParams_AllowsNormalParams(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/?page=1&sort=name&filter=critical", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("normal params: got %d, want 200", rec.Code)
	}
}

func TestRejectAPIKeyQueryParams_AllowsNoParams(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("no params: got %d, want 200", rec.Code)
	}
}

func TestRejectAPIKeyQueryParams_AllowsEmptyValues(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Empty values are not dangerous — the key isn't actually being transmitted.
	emptyVariants := []string{
		"/?api_key=",
		"/?token=",
		"/?access_token=",
		"/?api_key",
	}

	for _, url := range emptyVariants {
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("empty value %q: got %d, want 200", url, rec.Code)
			}
		})
	}
}

func TestRejectAPIKeyQueryParams_ResponseFormat(t *testing.T) {
	t.Parallel()

	handler := rejectAPIKeyQueryParams(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/?api_key=test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var body struct {
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", body.Status, http.StatusBadRequest)
	}
	if body.Detail == "" {
		t.Error("detail should not be empty")
	}
}
