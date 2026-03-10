// ABOUTME: Unit tests for the /healthz liveness endpoint.
// ABOUTME: Verifies that liveness returns 200 {"status":"alive"} with no external dependencies.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthzHandler_ReturnsAlive(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	healthzHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "alive" {
		t.Errorf("healthz status = %q, want %q", resp["status"], "alive")
	}
}

func TestHealthzHandler_ContentType(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	healthzHandler().ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}
