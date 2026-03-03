package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/scarson/cvert-ops/internal/api"
	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/store"
)

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
	cfg := &config.Config{Argon2MaxConcurrent: 5}
	apiSrv, err := api.NewServer(store.New(pool), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(apiSrv.Close)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)

	// ── /healthz ─────────────────────────────────────────────────────────────
	// Using srv.Client().Do with a literal path so gosec taint analysis sees
	// no user-controlled data flowing to the HTTP sink.
	hReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/healthz", nil)
	if err != nil {
		t.Fatalf("new request /healthz: %v", err)
	}
	resp, err := srv.Client().Do(hReq) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
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
	mReq, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("new request /metrics: %v", err)
	}
	mResp, err := srv.Client().Do(mReq) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
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
	cfg := &config.Config{Argon2MaxConcurrent: 5}
	apiSrv, err := api.NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(apiSrv.Close)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/healthz", nil)
	if err != nil {
		t.Fatalf("new request /healthz: %v", err)
	}
	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /healthz (nil db): %v", err)
	}
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

// newNilDBServer creates a Server with no DB (nil store) for testing middleware
// behavior that doesn't need a database (security headers, body limits, routing).
func newNilDBServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{Argon2MaxConcurrent: 5}
	apiSrv, err := api.NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(apiSrv.Close)
	srv := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// ── Security header tests ────────────────────────────────────────────────────

// TestSecurityHeaders_Healthz verifies that the three security headers defined
// in server.go are present on a successful /healthz response.
func TestSecurityHeaders_Healthz(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := newNilDBServer(t)

	// /healthz returns 503 with nil DB, but security headers must still be present.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/healthz", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	assertSecurityHeaders(t, resp)
}

// TestSecurityHeaders_404 verifies that security headers are present on a
// 404 response (the middleware runs before routing, so even unmatched paths
// must include them).
func TestSecurityHeaders_404(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := newNilDBServer(t)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/nonexistent-path", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET /nonexistent-path: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}

	assertSecurityHeaders(t, resp)
}

// assertSecurityHeaders checks that all three security headers are set
// with their expected values.
func assertSecurityHeaders(t *testing.T, resp *http.Response) {
	t.Helper()

	checks := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}
	for _, c := range checks {
		got := resp.Header.Get(c.header)
		if got != c.want {
			t.Errorf("header %s = %q, want %q", c.header, got, c.want)
		}
	}
}

// ── Body size limit test ─────────────────────────────────────────────────────

// TestBodySizeLimit verifies that the 1 MB request body limit middleware
// rejects oversized payloads. The middleware (middleware.RequestSize(1 << 20))
// is registered globally in server.go.
func TestBodySizeLimit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := newNilDBServer(t)

	// 1 MB = 1,048,576 bytes. Send 1 MB + 1 byte to exceed the limit.
	oversizedBody := bytes.Repeat([]byte("A"), (1<<20)+1)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/auth/register", bytes.NewReader(oversizedBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("POST oversized body: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// chi's RequestSize middleware returns 413 Request Entity Too Large.
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: got status %d, want %d", resp.StatusCode, http.StatusRequestEntityTooLarge)
	}
}

// ── Input validation tests ───────────────────────────────────────────────────

// TestPathTraversal_CVEEndpoint verifies that path traversal sequences in the
// cve_id path parameter do not leak file contents. Chi's router normalizes
// paths and huma validates the parameter, so this should return 404.
func TestPathTraversal_CVEEndpoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := newNilDBServer(t)

	// Attempt path traversal via the CVE detail endpoint.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/cves/..%2F..%2Fetc%2Fpasswd", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET path traversal: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Must not return 200. 404 or 301 (redirect from path normalization) are acceptable.
	if resp.StatusCode == http.StatusOK {
		t.Error("path traversal in cve_id returned 200 — possible directory traversal vulnerability")
	}
}

// TestNullByte_CVEEndpoint verifies that null bytes in the cve_id path
// parameter are handled safely (rejected or treated as a non-matching ID).
func TestNullByte_CVEEndpoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv := newNilDBServer(t)

	// %00 is a null byte — some backends truncate at null, potentially matching
	// a different resource than intended.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/cves/CVE-2024-1234%00injected", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := srv.Client().Do(req) //nolint:gosec // G704 false positive: srv.URL is httptest.Server, not user input
	if err != nil {
		t.Fatalf("GET null byte cve_id: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// The server should not treat this as a valid CVE lookup for "CVE-2024-1234".
	// 404 (not found) or 400 (bad request) are both acceptable.
	if resp.StatusCode == http.StatusOK {
		t.Error("null byte in cve_id returned 200 — possible null byte injection vulnerability")
	}
}
