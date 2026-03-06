// ABOUTME: Per-org API rate limiter keyed by organization UUID.
// ABOUTME: Supports different rates per org (tier-resolved) with idle eviction.
package api

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

type orgRateEntry struct {
	limiter *rate.Limiter
	lastAt  time.Time
}

type orgRateLimiter struct {
	mu       sync.Mutex
	entries  map[uuid.UUID]*orgRateEntry
	evictTTL time.Duration
	now      func() time.Time
	done     chan struct{}
}

func newOrgRateLimiter(now func() time.Time, evictTTL time.Duration) *orgRateLimiter {
	rl := &orgRateLimiter{
		entries:  make(map[uuid.UUID]*orgRateEntry),
		evictTTL: evictTTL,
		now:      now,
		done:     make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl
}

// Stop terminates the background cleanup goroutine.
func (rl *orgRateLimiter) Stop() {
	close(rl.done)
}

// Allow reports whether the given org is within its rate limit. If the stored
// limiter's rate or burst differs from the requested values (e.g., after a tier
// change), a new limiter is created with the updated parameters.
func (rl *orgRateLimiter) Allow(orgID uuid.UUID, r rate.Limit, burst int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	e, ok := rl.entries[orgID]
	if !ok || e.limiter.Limit() != r || e.limiter.Burst() != burst {
		e = &orgRateEntry{limiter: rate.NewLimiter(r, burst)}
		rl.entries[orgID] = e
	}
	e.lastAt = rl.now()
	return e.limiter.Allow()
}

func (rl *orgRateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.evictTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.evictIdle()
		case <-rl.done:
			return
		}
	}
}

func (rl *orgRateLimiter) evictIdle() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := rl.now().Add(-rl.evictTTL)
	for id, e := range rl.entries {
		if e.lastAt.Before(cutoff) {
			delete(rl.entries, id)
		}
	}
}
