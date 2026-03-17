// ABOUTME: Tests for the /readyz readiness endpoint.
// ABOUTME: Verifies DB connectivity, migration currency, and worker status checks.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/scarson/cvert-ops/internal/testutil"
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
			Dirty   bool   `json:"dirty"`
		} `json:"migrations"`
		Worker struct {
			Goroutines int `json:"goroutines"`
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

func TestReadyzHandler_DirtyMigration_Returns503(t *testing.T) {
	t.Parallel()

	db := testutil.NewTestDB(t)
	pool := db.Pool()
	ctx := context.Background()

	// Read current schema version.
	var version int
	if err := pool.QueryRow(ctx, "SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1").Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}

	// Set dirty flag.
	if _, err := pool.Exec(ctx, "UPDATE schema_migrations SET dirty = true WHERE version = $1", version); err != nil {
		t.Fatalf("set dirty flag: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "UPDATE schema_migrations SET dirty = false WHERE version = $1", version)
	})

	handler := readyzHandler(pool, version)
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readyz with dirty migration: got %d, want 503", rec.Code)
	}

	var resp readyzResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Checks.Migrations.Status != "dirty" {
		t.Errorf("migration status = %q, want %q", resp.Checks.Migrations.Status, "dirty")
	}
	if !resp.Checks.Migrations.Dirty {
		t.Error("migration dirty field should be true")
	}
}

// Ensure the handler signature compiles with a real pool type.
var _ = func(db *pgxpool.Pool) {
	_ = readyzHandler(db, 34)
}
