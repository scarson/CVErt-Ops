// ABOUTME: Per-IP in-memory rate limiter for auth endpoints.
// ABOUTME: Uses golang.org/x/time/rate with background cleanup of idle entries.
package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	burst    int
	evictTTL time.Duration
	lastSeen map[string]time.Time
}

func newIPRateLimiter(r rate.Limit, burst int, evictTTL time.Duration) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		lastSeen: make(map[string]time.Time),
		r:        r,
		burst:    burst,
		evictTTL: evictTTL,
	}
	go rl.cleanupLoop()
	return rl
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
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.evictTTL)
		for ip, last := range rl.lastSeen {
			if last.Before(cutoff) {
				delete(rl.limiters, ip)
				delete(rl.lastSeen, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// authRateLimit returns a middleware that applies per-IP rate limiting.
// The IP is extracted from r.RemoteAddr — chi's RealIP middleware must run first
// so X-Forwarded-For is honoured for requests behind a reverse proxy.
func (srv *Server) authRateLimit() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}
			if !srv.rateLimiter.Allow(ip) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
