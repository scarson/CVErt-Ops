// ABOUTME: Per-org rate limiter for SCIM endpoints.
// ABOUTME: Separate from the API rate limiter. Keyed by org_id UUID from context.
package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/scarson/cvert-ops/internal/secure"
)

type scimRateLimiter struct {
	mu       sync.Mutex
	limiters map[uuid.UUID]*scimRateEntry
	r        rate.Limit
	burst    int
	evictTTL time.Duration
	done     chan struct{}
}

type scimRateEntry struct {
	limiter *rate.Limiter
	lastAt  time.Time
}

func newSCIMRateLimiter(r rate.Limit, burst int, evictTTL time.Duration) *scimRateLimiter {
	rl := &scimRateLimiter{
		limiters: make(map[uuid.UUID]*scimRateEntry),
		r:        r,
		burst:    burst,
		evictTTL: evictTTL,
		done:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *scimRateLimiter) Stop() {
	close(rl.done)
}

// Allow reports whether the given org is within its SCIM rate limit.
func (rl *scimRateLimiter) Allow(orgID uuid.UUID) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.limiters[orgID]
	if !ok {
		e = &scimRateEntry{limiter: rate.NewLimiter(rl.r, rl.burst)}
		rl.limiters[orgID] = e
	}
	e.lastAt = time.Now()
	return e.limiter.Allow()
}

func (rl *scimRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.evictTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.evictTTL)
			for id, e := range rl.limiters {
				if e.lastAt.Before(cutoff) {
					delete(rl.limiters, id)
				}
			}
			rl.mu.Unlock()
		case <-rl.done:
			return
		}
	}
}

// scimRateLimit returns a chi middleware that enforces per-org SCIM rate limiting.
// Must run after requireSCIMAuth (which injects ctxOrgID into context).
// The rate limiter is stored on the Server and stopped via Close().
func (srv *Server) scimRateLimit() func(http.Handler) http.Handler {
	rateVal := srv.cfg.SCIMRateLimit
	if rateVal <= 0 {
		rateVal = 50
	}
	rl := newSCIMRateLimiter(rate.Limit(rateVal), int(rateVal), 15*time.Minute)
	srv.scimRL = rl

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID, ok := r.Context().Value(ctxOrgID).(uuid.UUID)
			if !ok {
				writeSCIMError(w, http.StatusInternalServerError, "", "internal error")
				return
			}

			if !rl.Allow(orgID) {
				srv.fireSCIMEvent(r.Context(), secure.EventSCIMRateLimited, &orgID)
				w.Header().Set("Retry-After", "1")
				writeSCIMError(w, http.StatusTooManyRequests, "", "Rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
