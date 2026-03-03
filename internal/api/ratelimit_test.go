// ABOUTME: Tests for per-IP in-memory rate limiter and authRateLimit middleware.
// ABOUTME: Uses package api (not api_test) to access unexported Server fields.
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestIPRateLimiter_Allow(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(rate.Limit(100), 3, time.Minute)
	for i := 1; i <= 3; i++ {
		if !rl.Allow("127.0.0.1") {
			t.Errorf("request %d: should be allowed (within burst of 3)", i)
		}
	}
	if rl.Allow("127.0.0.1") {
		t.Error("4th request: should be denied (burst of 3 exhausted)")
	}
}

func TestIPRateLimiter_SeparateBucketsPerIP(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(rate.Limit(1), 1, time.Minute)
	if !rl.Allow("1.2.3.4") {
		t.Error("1.2.3.4 first request should be allowed")
	}
	if rl.Allow("1.2.3.4") {
		t.Error("1.2.3.4 second request should be denied")
	}
	if !rl.Allow("5.6.7.8") {
		t.Error("5.6.7.8 first request should be allowed (independent bucket)")
	}
}

func TestIPRateLimiter_Stop(t *testing.T) {
	t.Parallel()
	rl := newIPRateLimiter(rate.Limit(1), 1, 100*time.Millisecond)

	// Use the limiter to create an entry.
	rl.Allow("1.2.3.4")

	// Stop should not panic or hang.
	rl.Stop()

	// After stop, Allow still works (stateless check, no cleanup goroutine needed).
	if !rl.Allow("5.6.7.8") {
		t.Error("Allow should still work after Stop")
	}
}

func TestAuthRateLimit_Returns429AfterBurst(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 2, time.Minute),
	}
	handler := srv.authRateLimit()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
		if err != nil {
			t.Fatalf("request %d: new request: %v", i, err)
		}
		resp, err := ts.Client().Do(req) //nolint:gosec // G704 false positive: ts.URL is httptest.Server, not user input
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test
		wantStatus := http.StatusOK
		if i > 2 {
			wantStatus = http.StatusTooManyRequests
		}
		if resp.StatusCode != wantStatus {
			t.Errorf("request %d: got status %d, want %d", i, resp.StatusCode, wantStatus)
		}
	}
}

func TestAuthRateLimit_RetryAfterHeader(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 1, time.Minute),
	}
	handler := srv.authRateLimit()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	ctx := context.Background()
	// First request: allowed (burst=1).
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp, _ := ts.Client().Do(req) //nolint:gosec // G704 false positive
	resp.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	// Second request: rate limited → must include Retry-After header.
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	resp2, err := ts.Client().Do(req2) //nolint:gosec // G704 false positive
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	resp2.Body.Close() //nolint:errcheck,gosec // G104: body close in test

	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request: got status %d, want 429", resp2.StatusCode)
	}
	if ra := resp2.Header.Get("Retry-After"); ra == "" {
		t.Error("rate-limited response missing Retry-After header")
	}
}

// TestClientIPMiddleware_SetsContextIP verifies that clientIPMiddleware
// extracts the IP from RemoteAddr and injects it into the context.
func TestClientIPMiddleware_SetsContextIP(t *testing.T) {
	t.Parallel()
	var gotIP string
	handler := clientIPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, _ = r.Context().Value(ctxClientIP).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if gotIP != "192.168.1.100" {
		t.Errorf("ctxClientIP = %q, want %q", gotIP, "192.168.1.100")
	}
}

// TestClientIPMiddleware_NoPort verifies that clientIPMiddleware handles
// RemoteAddr without a port (net.SplitHostPort fails, falls back to raw value).
func TestClientIPMiddleware_NoPort(t *testing.T) {
	t.Parallel()
	var gotIP string
	handler := clientIPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, _ = r.Context().Value(ctxClientIP).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "10.0.0.1" {
		t.Errorf("ctxClientIP = %q, want %q", gotIP, "10.0.0.1")
	}
}

// TestClientIPMiddleware_IPv6 verifies that clientIPMiddleware correctly
// parses an IPv6 address with port from RemoteAddr.
func TestClientIPMiddleware_IPv6(t *testing.T) {
	t.Parallel()
	var gotIP string
	handler := clientIPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIP, _ = r.Context().Value(ctxClientIP).(string)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "[::1]:8080"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if gotIP != "::1" {
		t.Errorf("ctxClientIP = %q, want %q", gotIP, "::1")
	}
}

// TestCheckAuthRateLimit_AllowsWithinBurst verifies that checkAuthRateLimit
// returns nil when requests are within the burst limit.
func TestCheckAuthRateLimit_AllowsWithinBurst(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 3, time.Minute),
	}

	ctx := context.WithValue(context.Background(), ctxClientIP, "10.0.0.1")
	for i := 1; i <= 3; i++ {
		if err := srv.checkAuthRateLimit(ctx); err != nil {
			t.Errorf("request %d: checkAuthRateLimit returned error within burst: %v", i, err)
		}
	}
}

// TestCheckAuthRateLimit_ReturnsErrorAfterBurst verifies that checkAuthRateLimit
// returns a huma 429 error after the burst is exhausted.
func TestCheckAuthRateLimit_ReturnsErrorAfterBurst(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 1, time.Minute),
	}

	ctx := context.WithValue(context.Background(), ctxClientIP, "10.0.0.2")
	// First request: within burst.
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		t.Fatalf("first request: unexpected error: %v", err)
	}
	// Second request: exceeds burst.
	err := srv.checkAuthRateLimit(ctx)
	if err == nil {
		t.Fatal("second request: expected error after burst exhausted, got nil")
	}
}

// TestCheckAuthRateLimit_MissingIPUsesUnknown verifies that when ctxClientIP
// is not set in context, checkAuthRateLimit falls back to "unknown" as the IP.
func TestCheckAuthRateLimit_MissingIPUsesUnknown(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 1, time.Minute),
	}

	// No ctxClientIP in context — should use "unknown" as the IP key.
	ctx := context.Background()
	if err := srv.checkAuthRateLimit(ctx); err != nil {
		t.Fatalf("first request with missing IP: unexpected error: %v", err)
	}
	// Second request to "unknown" bucket should be rate limited.
	err := srv.checkAuthRateLimit(ctx)
	if err == nil {
		t.Error("second request with missing IP: expected rate limit error, got nil")
	}
}

// TestAuthRateLimit_ExtractsIPFromHostPort verifies that authRateLimit
// correctly strips the port from RemoteAddr before rate limiting.
func TestAuthRateLimit_ExtractsIPFromHostPort(t *testing.T) {
	t.Parallel()
	srv := &Server{ //nolint:exhaustruct // test: only rateLimiter needed
		rateLimiter: newIPRateLimiter(rate.Limit(100), 1, time.Minute),
	}

	handler := srv.authRateLimit()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Request from same IP but different ports should share the same bucket.
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req1.RemoteAddr = "172.16.0.1:11111"
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	req2.RemoteAddr = "172.16.0.1:22222"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request (same IP, different port): got %d, want 429", rec2.Code)
	}
}
