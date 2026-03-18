// ABOUTME: Tests for the API key query parameter rejection middleware.
// ABOUTME: Verifies that sensitive parameters in URLs are blocked, and normal requests pass through.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
