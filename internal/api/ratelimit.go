// ABOUTME: Per-IP in-memory rate limiter for auth endpoints, and client IP resolution
// ABOUTME: that honours forwarded headers only from TRUSTED_PROXIES.
package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	burst    int
	evictTTL time.Duration
	lastSeen map[string]time.Time
	done     chan struct{}
}

func newIPRateLimiter(r rate.Limit, burst int, evictTTL time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		r:        r,
		burst:    burst,
		evictTTL: evictTTL,
		done:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *ipRateLimiter) Stop() {
	close(rl.done)
}

// Allow reports whether the given IP is within its rate limit.
func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	l, ok := rl.limiters[ip]
	if !ok {
		l = rate.NewLimiter(rl.r, rl.burst)
		rl.limiters[ip] = l
	}
	rl.lastSeen[ip] = time.Now()
	return l.Allow()
}

func (rl *ipRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.evictTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.evictTTL)
			for ip, last := range rl.lastSeen {
				if last.Before(cutoff) {
					delete(rl.limiters, ip)
					delete(rl.lastSeen, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.done:
			return
		}
	}
}

// authRateLimit returns a middleware that applies per-IP rate limiting.
// The IP comes from ctxClientIP, so clientIPMiddleware must run first.
func (srv *Server) authRateLimit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !srv.rateLimiter.Allow(clientIP(r.Context())) {
				w.Header().Set("Retry-After", "60")
				writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// parseTrustedProxies splits the TRUSTED_PROXIES value into CIDR prefixes and
// rejects any entry that is not one, so a typo fails startup instead of
// silently disabling (or widening) forwarded-header trust.
func parseTrustedProxies(value string) ([]string, error) {
	var prefixes []string
	for _, p := range strings.Split(value, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := netip.ParsePrefix(p); err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q is not a CIDR network (use 10.0.0.5/32 for a single proxy)", p)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// clientIPMiddleware resolves the client IP and injects it into the context as
// ctxClientIP, where the auth rate limiters, audit log and security events read
// it. With no trusted proxies the IP is the TCP peer and forwarded headers are
// ignored. Otherwise X-Forwarded-For is honoured only when the peer is inside
// trustedProxies, and the client is its rightmost entry outside them.
//
// When chi resolves no IP (the peer is a trusted proxy that sent no untrusted
// X-Forwarded-For entry, or an entry did not parse), the TCP peer is used: it
// cannot be spoofed, and it is what PLAN.md specifies when every hop is trusted.
//
// It also sets ctxTrustedProxyPeer, so code reading other forwarded headers
// (X-Forwarded-Proto) can apply the same trust decision.
func clientIPMiddleware(trustedProxies []string) func(http.Handler) http.Handler {
	resolve := middleware.ClientIPFromRemoteAddr
	if len(trustedProxies) > 0 {
		resolve = middleware.ClientIPFromXFF(trustedProxies...)
	}
	prefixes := make([]netip.Prefix, len(trustedProxies))
	for i, p := range trustedProxies {
		prefixes[i] = netip.MustParsePrefix(p) // validated by parseTrustedProxies
	}
	return func(next http.Handler) http.Handler {
		return resolve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := middleware.GetClientIP(r.Context())
			if ip == "" {
				ip = r.RemoteAddr
				if host, _, err := net.SplitHostPort(ip); err == nil {
					ip = host
				}
			}
			ctx := context.WithValue(r.Context(), ctxClientIP, ip)
			ctx = context.WithValue(ctx, ctxTrustedProxyPeer, peerInPrefixes(r.RemoteAddr, prefixes))
			next.ServeHTTP(w, r.WithContext(ctx))
		}))
	}
}

// peerInPrefixes reports whether the host of remoteAddr falls within any of
// prefixes. v4-mapped addresses fold to v4 and zones are stripped, as chi does,
// so neither notation can alias a trusted address past the check.
func peerInPrefixes(remoteAddr string, prefixes []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap().WithZone("")
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP extracts the client IP address from the request context.
// Returns "unknown" if the middleware hasn't injected it.
func clientIP(ctx context.Context) string {
	ip, _ := ctx.Value(ctxClientIP).(string)
	if ip == "" {
		return "unknown"
	}
	return ip
}

// checkAuthRateLimit checks the per-IP rate limiter using the client IP from
// context. Returns a huma error if the rate limit is exceeded, nil otherwise.
func (srv *Server) checkAuthRateLimit(ctx context.Context) error {
	ip := clientIP(ctx)
	if !srv.rateLimiter.Allow(ip) {
		return huma.Error429TooManyRequests("rate limit exceeded; retry after 60 seconds")
	}
	return nil
}
