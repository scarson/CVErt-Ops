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
