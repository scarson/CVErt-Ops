// ABOUTME: Tests for the /readyz readiness endpoint.
// ABOUTME: Verifies DB connectivity, migration currency, and worker status checks.
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// readyzResponse mirrors the JSON structure returned by readyzHandler.
type readyzResponse struct {
	Status string `json:"status"`
	Checks struct {
		Database struct {
			Status    string `json:"status"`
			LatencyMS int64  `json:"latency_ms"`
		} `json:"database"`
		Migrations struct {
			Status  string `json:"status"`
			Version int    `json:"version"`
		} `json:"migrations"`
		Worker struct {
			Status     string `json:"status"`
			Goroutines int    `json:"goroutines"`
		} `json:"worker"`
	} `json:"checks"`
}

func TestReadyzHandler_NilDB_Returns503(t *testing.T) {
	t.Parallel()

	handler := readyzHandler(nil, 34)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz with nil DB: got %d, want 503", rec.Code)
	}

	var resp readyzResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != "not_ready" {
		t.Errorf("status = %q, want %q", resp.Status, "not_ready")
	}
	if resp.Checks.Database.Status != "down" {
		t.Errorf("database status = %q, want %q", resp.Checks.Database.Status, "down")
	}
}

func TestReadyzHandler_ContentType(t *testing.T) {
	t.Parallel()

	handler := readyzHandler(nil, 34)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
}

// TestReadyzHandler_WithDB is tested via integration test in smoke_test.go.
// The unit test here just verifies nil-DB behavior since we can't easily
// create a pgxpool in a unit test without a real Postgres.

// Ensure the handler signature compiles with a real pool type.
var _ = func(db *pgxpool.Pool) {
	_ = readyzHandler(db, 34)
}
