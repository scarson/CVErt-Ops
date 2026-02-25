package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/scarson/cvert-ops/internal/api"
)

// get issues a GET request using NewRequestWithContext and returns the response.
// Fails the test immediately on any error.
func get(t *testing.T, ctx context.Context, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

// TestSmokeHealthz starts a real Postgres container, builds the HTTP handler,
// and asserts that /healthz returns 200 {"status":"ok"} and /metrics returns 200.
//
// This is a coarse integration test: if it passes, the router wiring, DB pool
// creation, and Prometheus handler are all operational. It is intentionally
// minimal — Phase 1 will add more targeted tests per feature.
func TestSmokeHealthz(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// ── Start Postgres container ──────────────────────────────────────────────
	pgCtr, err := tcpostgres.Run(ctx,
		"postgres:18-alpine",
		tcpostgres.WithDatabase("cvert_ops_test"),
		tcpostgres.WithUsername("cvert_ops_test"),
		tcpostgres.WithPassword("testpassword"),
		tcpostgres.BasicWaitStrategies(), // waits for "ready to accept connections" ×2 + port
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := pgCtr.Terminate(ctx); err != nil {
			t.Logf("terminate postgres container: %v", err)
		}
	})

	connStr, err := pgCtr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	// ── Connect pgxpool ───────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Fatalf("open pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping db: %v", err)
	}

	// ── Build handler and test server ────────────────────────────────────────
	handler := api.NewRouter(pool)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	// ── /healthz ─────────────────────────────────────────────────────────────
	resp := get(t, ctx, srv.URL+"/healthz")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz: got status %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /healthz body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("GET /healthz: got status %q, want %q", body.Status, "ok")
	}

	// ── /metrics ─────────────────────────────────────────────────────────────
	mResp := get(t, ctx, srv.URL+"/metrics")
	defer mResp.Body.Close() //nolint:errcheck

	if mResp.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics: got status %d, want %d", mResp.StatusCode, http.StatusOK)
	}
}

// TestSmokeHealthzDegraded verifies that /healthz returns 503 when the DB pool
// is nil (simulating an unavailable database).
func TestSmokeHealthzDegraded(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	handler := api.NewRouter(nil)
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	resp := get(t, ctx, srv.URL+"/healthz")
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("GET /healthz (nil db): got status %d, want %d",
			resp.StatusCode, http.StatusServiceUnavailable)
	}

	var body struct {
		Status string `json:"status"`
		DB     string `json:"db"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /healthz body: %v", err)
	}
	if body.Status != "degraded" {
		t.Errorf("GET /healthz (nil db): got status %q, want %q", body.Status, "degraded")
	}
	if body.DB != "unavailable" {
		t.Errorf("GET /healthz (nil db): got db %q, want %q", body.DB, "unavailable")
	}
}
