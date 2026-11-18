// ABOUTME: Tests that the auth rate limiter keys on the real client IP, honouring
// ABOUTME: forwarded headers only from TRUSTED_PROXIES and rejecting invalid CIDRs.
package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/config"
)

// authRateLimitBurst is the per-IP burst NewServer gives the auth rate limiter.
const authRateLimitBurst = 10

// rateLimitedPath is a chi route wrapped in authRateLimit. With GitHub OAuth
// unconfigured it answers 501 without touching the database, so any 429 comes
// from the rate limiter.
const rateLimitedPath = "/api/v1/auth/oauth/github"

func newClientIPTestHandler(t *testing.T, trustedProxies string) http.Handler {
	t.Helper()
	cfg := &config.Config{Argon2MaxConcurrent: 1, TrustedProxies: trustedProxies} //nolint:exhaustruct // test
	srv, err := NewServer(nil, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv.Handler()
}

func serveRateLimited(h http.Handler, remoteAddr string, headers map[string]string) int {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, rateLimitedPath, nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestAuthRateLimit_IgnoresForwardedHeadersWithoutTrustedProxies verifies that
// with TRUSTED_PROXIES empty, a client cannot get a fresh rate-limit bucket by
// varying X-Forwarded-For, X-Real-IP or True-Client-IP: every request is keyed
// on the TCP peer address.
func TestAuthRateLimit_IgnoresForwardedHeadersWithoutTrustedProxies(t *testing.T) {
	t.Parallel()
	h := newClientIPTestHandler(t, "")

	for i := 1; i <= authRateLimitBurst; i++ {
		spoofed := fmt.Sprintf("198.51.100.%d", i)
		code := serveRateLimited(h, "203.0.113.7:40000", map[string]string{
			"X-Forwarded-For": spoofed,
			"X-Real-IP":       spoofed,
			"True-Client-IP":  spoofed,
		})
		if code != http.StatusNotImplemented {
			t.Fatalf("request %d within burst: got %d, want 501", i, code)
		}
	}

	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "True-Client-IP"} {
		code := serveRateLimited(h, "203.0.113.7:40001", map[string]string{header: "192.0.2.99"})
		if code != http.StatusTooManyRequests {
			t.Errorf("spoofed %s after burst: got %d, want 429 (keyed on RemoteAddr)", header, code)
		}
	}

	if code := serveRateLimited(h, "203.0.113.8:40000", nil); code != http.StatusNotImplemented {
		t.Errorf("different RemoteAddr: got %d, want 501 (independent bucket)", code)
	}
}

// TestAuthRateLimit_UsesRightmostUntrustedHopFromTrustedProxy verifies that a
// request from inside TRUSTED_PROXIES is keyed on the rightmost X-Forwarded-For
// entry outside the trusted CIDRs, and that client-supplied entries to the left
// of it are ignored.
func TestAuthRateLimit_UsesRightmostUntrustedHopFromTrustedProxy(t *testing.T) {
	t.Parallel()
	h := newClientIPTestHandler(t, "10.0.0.0/8")

	for i := 1; i <= authRateLimitBurst; i++ {
		// Leftmost hop is attacker-controlled and changes on every request;
		// 10.0.0.9 is a trusted proxy hop that appended the client address.
		xff := fmt.Sprintf("198.51.100.%d, 203.0.113.7, 10.0.0.9", i)
		code := serveRateLimited(h, "10.0.0.5:40000", map[string]string{"X-Forwarded-For": xff})
		if code != http.StatusNotImplemented {
			t.Fatalf("request %d within burst: got %d, want 501", i, code)
		}
	}

	code := serveRateLimited(h, "10.0.0.5:40000", map[string]string{"X-Forwarded-For": "192.0.2.99, 203.0.113.7"})
	if code != http.StatusTooManyRequests {
		t.Errorf("same client behind proxy after burst: got %d, want 429", code)
	}

	// Another client behind the same proxy has its own bucket, so the limiter
	// is not keyed on the proxy address.
	code = serveRateLimited(h, "10.0.0.5:40000", map[string]string{"X-Forwarded-For": "203.0.113.8"})
	if code != http.StatusNotImplemented {
		t.Errorf("different client behind proxy: got %d, want 501", code)
	}
}

// TestAuthRateLimit_IgnoresForwardedHeadersFromUntrustedPeer verifies that a
// client connecting directly, outside TRUSTED_PROXIES, is keyed on its own
// address even when it sends X-Forwarded-For.
func TestAuthRateLimit_IgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	t.Parallel()
	h := newClientIPTestHandler(t, "10.0.0.0/8")

	for i := 1; i <= authRateLimitBurst; i++ {
		xff := fmt.Sprintf("198.51.100.%d", i)
		code := serveRateLimited(h, "203.0.113.7:40000", map[string]string{"X-Forwarded-For": xff})
		if code != http.StatusNotImplemented {
			t.Fatalf("request %d within burst: got %d, want 501", i, code)
		}
	}
	code := serveRateLimited(h, "203.0.113.7:40000", map[string]string{"X-Forwarded-For": "192.0.2.99"})
	if code != http.StatusTooManyRequests {
		t.Errorf("direct client after burst: got %d, want 429 (keyed on RemoteAddr)", code)
	}
}

// TestClientIPMiddleware_ResolvesClientIP verifies the ctxClientIP value that
// huma auth handlers rate-limit on and audit/security events record.
func TestClientIPMiddleware_ResolvesClientIP(t *testing.T) {
	t.Parallel()
	trusted := []string{"10.0.0.0/8", "fd00::/8"}
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no trusted proxies ignores forwarded headers",
			remoteAddr: "203.0.113.7:40000",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1", "X-Real-IP": "198.51.100.2", "True-Client-IP": "198.51.100.3"},
			want:       "203.0.113.7",
		},
		{
			name:       "no trusted proxies folds v4-mapped peer",
			remoteAddr: "[::ffff:203.0.113.7]:40000",
			want:       "203.0.113.7",
		},
		{
			name:       "trusted peer uses rightmost untrusted hop",
			trusted:    trusted,
			remoteAddr: "10.0.0.5:40000",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1, 203.0.113.7, 10.0.0.9"},
			want:       "203.0.113.7",
		},
		{
			name:       "trusted peer ignores X-Real-IP and True-Client-IP",
			trusted:    trusted,
			remoteAddr: "10.0.0.5:40000",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7", "X-Real-IP": "198.51.100.2", "True-Client-IP": "198.51.100.3"},
			want:       "203.0.113.7",
		},
		{
			name:       "trusted IPv6 peer",
			trusted:    trusted,
			remoteAddr: "[fd00::5]:40000",
			headers:    map[string]string{"X-Forwarded-For": "2001:db8::7"},
			want:       "2001:db8::7",
		},
		{
			name:       "untrusted peer ignores X-Forwarded-For",
			trusted:    trusted,
			remoteAddr: "203.0.113.7:40000",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.9"},
			want:       "203.0.113.7",
		},
		{
			name:       "trusted peer without X-Forwarded-For falls back to peer",
			trusted:    trusted,
			remoteAddr: "10.0.0.5:40000",
			want:       "10.0.0.5",
		},
		{
			name:       "trusted peer with only trusted hops falls back to peer",
			trusted:    trusted,
			remoteAddr: "10.0.0.5:40000",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.8, 10.0.0.9"},
			want:       "10.0.0.5",
		},
		{
			name:       "unparseable hop falls back to peer, not to hops left of it",
			trusted:    trusted,
			remoteAddr: "10.0.0.5:40000",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1, garbage"},
			want:       "10.0.0.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got, gotRemoteAddr string
			handler := clientIPMiddleware(tt.trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				got, _ = r.Context().Value(ctxClientIP).(string)
				gotRemoteAddr = r.RemoteAddr
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/test", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)
			if got != tt.want {
				t.Errorf("ctxClientIP = %q, want %q", got, tt.want)
			}
			if gotRemoteAddr != tt.remoteAddr {
				t.Errorf("RemoteAddr rewritten to %q; must stay the TCP peer", gotRemoteAddr)
			}
		})
	}
}

// TestNewServer_TrustedProxies verifies that TRUSTED_PROXIES is validated at
// startup: every comma-separated entry must be a CIDR prefix.
func TestNewServer_TrustedProxies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		wantErr string // empty means NewServer must succeed
	}{
		{name: "empty", value: ""},
		{name: "single IPv4", value: "10.0.0.0/8"},
		{name: "list with spaces", value: " 10.0.0.0/8 , 172.16.0.0/12,fd00::/8 "},
		{name: "bare IP", value: "10.0.0.5", wantErr: `"10.0.0.5"`},
		{name: "not an address", value: "10.0.0.0/8,proxy.internal", wantErr: `"proxy.internal"`},
		{name: "prefix too long", value: "10.0.0.0/33", wantErr: `"10.0.0.0/33"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{Argon2MaxConcurrent: 1, TrustedProxies: tt.value} //nolint:exhaustruct // test
			srv, err := NewServer(nil, cfg, ServerDeps{})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewServer(TRUSTED_PROXIES=%q): %v", tt.value, err)
				}
				srv.Close()
				return
			}
			if err == nil {
				srv.Close()
				t.Fatalf("NewServer(TRUSTED_PROXIES=%q): got nil error, want one naming %s", tt.value, tt.wantErr)
			}
			if !strings.Contains(err.Error(), "TRUSTED_PROXIES") || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to name TRUSTED_PROXIES and %s", err, tt.wantErr)
			}
		})
	}
}
