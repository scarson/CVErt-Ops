// ABOUTME: Tests for CORS middleware configuration and origin enforcement.
// ABOUTME: Verifies preflight, actual requests, disallowed origins, and dev defaults.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
)

// newCORSServer creates a minimal Server with the given CORS config for testing.
// No database is needed — tests hit /healthz which works without a DB.
func newCORSServer(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	srv, err := NewServer(nil, cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Close)
	return ts
}

func TestCORS_PreflightAllowedOrigin(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		CORSAllowedOrigins:  "https://app.example.com",
		Argon2MaxConcurrent: 1,
	})

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, ts.URL+"/api/v1/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Content-Type")

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}
}

func TestCORS_PreflightDisallowedOrigin(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		CORSAllowedOrigins:  "https://app.example.com",
		Argon2MaxConcurrent: 1,
	})

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodOptions, ts.URL+"/api/v1/auth/login", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty for disallowed origin", got)
	}
}

func TestCORS_ActualRequestWithCredentials(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		CORSAllowedOrigins:  "https://app.example.com",
		Argon2MaxConcurrent: 1,
	})

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://app.example.com")

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("actual request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://app.example.com")
	}
	if got := resp.Header.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, want %q", got, "true")
	}
	if got := resp.Header.Get("Access-Control-Expose-Headers"); got != "X-Request-Id" {
		t.Errorf("Access-Control-Expose-Headers = %q, want %q", got, "X-Request-Id")
	}
}

func TestCORS_NoConfigNoHeaders(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		AppEnv:              "production",
		Argon2MaxConcurrent: 1,
	})

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("Origin", "https://anything.example.com")

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (no CORS in production without config)", got)
	}
}

func TestCORS_MultipleOriginsWithWhitespace(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		CORSAllowedOrigins:  " https://a.example.com , https://b.example.com , ",
		Argon2MaxConcurrent: 1,
	})

	ctx := context.Background()

	// First origin (with leading whitespace in config) should work.
	req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req1.Header.Set("Origin", "https://a.example.com")
	resp1, err := ts.Client().Do(req1) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp1.Body.Close() //nolint:errcheck,gosec // G104
	if got := resp1.Header.Get("Access-Control-Allow-Origin"); got != "https://a.example.com" {
		t.Errorf("origin A: Access-Control-Allow-Origin = %q, want %q", got, "https://a.example.com")
	}

	// Second origin should also work.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req2.Header.Set("Origin", "https://b.example.com")
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp2.Body.Close() //nolint:errcheck,gosec // G104
	if got := resp2.Header.Get("Access-Control-Allow-Origin"); got != "https://b.example.com" {
		t.Errorf("origin B: Access-Control-Allow-Origin = %q, want %q", got, "https://b.example.com")
	}

	// Trailing empty segment from config should not match empty origin.
	req3, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req3.Header.Set("Origin", "https://evil.example.com")
	resp3, err := ts.Client().Do(req3) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp3.Body.Close() //nolint:errcheck,gosec // G104
	if got := resp3.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("evil origin: Access-Control-Allow-Origin = %q, want empty", got)
	}
}

func TestCORS_DevelopmentDefaults(t *testing.T) {
	t.Parallel()
	ts := newCORSServer(t, &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		JWTSecret:           "cors-test-secret",
		AppEnv:              "development",
		Argon2MaxConcurrent: 1,
		// No CORSAllowedOrigins — dev defaults should kick in
	})

	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/healthz", nil)
	req.Header.Set("Origin", "http://localhost:5173")

	resp, err := ts.Client().Do(req) //nolint:gosec // G704 test server URL
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close() //nolint:errcheck,gosec // G104

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q (dev default)", got, "http://localhost:5173")
	}
}
