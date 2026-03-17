// ABOUTME: In-memory TTL-based rate limiter for security event writes.
// ABOUTME: Limits events per (event_type, actor_ip) to prevent write floods.
package secure

import (
	"sync"
	"time"
)

// eventRateLimiter tracks event counts per (event_type, actor_ip) key within
// a sliding window. Entries are evicted after a configurable TTL of inactivity.
type eventRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    int
	window   time.Duration
	ttl      time.Duration
	done     chan struct{}
	stopOnce sync.Once
	now      func() time.Time // injectable clock for testing
}

type bucket struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

// newEventRateLimiter creates a rate limiter that allows limit events per window
// for each unique key. Stale entries are evicted when not seen for ttl.
// The eviction goroutine runs every ttl/2.
func newEventRateLimiter(limit int, window, ttl time.Duration, now func() time.Time) *eventRateLimiter {
	if now == nil {
		now = time.Now
	}
	rl := &eventRateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		window:  window,
		ttl:     ttl,
		done:    make(chan struct{}),
		now:     now,
	}
	go rl.evictLoop()
	return rl
}

// Allow checks whether an event with the given key is within the rate limit.
// Returns true if the event should be written, false if it should be dropped.
func (rl *eventRateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{
			count:       1,
			windowStart: now,
			lastSeen:    now,
		}
		return true
	}

	b.lastSeen = now

	// Reset window if it has elapsed.
	if now.Sub(b.windowStart) >= rl.window {
		b.count = 1
		b.windowStart = now
		return true
	}

	if b.count >= rl.limit {
		return false
	}
	b.count++
	return true
}

// Stop signals the eviction goroutine to exit. Safe to call multiple times.
func (rl *eventRateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.done) })
}

// evictLoop periodically removes buckets that haven't been seen within ttl.
func (rl *eventRateLimiter) evictLoop() {
	interval := rl.ttl / 2
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.evict()
		}
	}
}

// evict removes stale entries under lock.
func (rl *eventRateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.now()
	for k, b := range rl.buckets {
		if now.Sub(b.lastSeen) > rl.ttl {
			delete(rl.buckets, k)
		}
	}
}
