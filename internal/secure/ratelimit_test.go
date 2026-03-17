// ABOUTME: Tests for the security event rate limiter — window enforcement, TTL eviction, Stop().
// ABOUTME: Uses an injectable clock to avoid flaky time-dependent tests.
package secure

import (
	"sync"
	"testing"
	"time"
)

func TestEventRateLimiter_BasicLimit(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock := func() time.Time { return now }
	rl := newEventRateLimiter(3, time.Minute, 5*time.Minute, clock)
	defer rl.Stop()

	key := "auth.login_failed|10.0.0.1"
	for i := 0; i < 3; i++ {
		if !rl.Allow(key) {
			t.Fatalf("Allow() returned false on attempt %d, expected true", i+1)
		}
	}
	if rl.Allow(key) {
		t.Fatal("Allow() returned true after limit reached, expected false")
	}
}

func TestEventRateLimiter_WindowReset(t *testing.T) {
	t.Parallel()

	mu := sync.Mutex{}
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(d)
	}

	rl := newEventRateLimiter(2, time.Minute, 5*time.Minute, clock)
	defer rl.Stop()

	key := "auth.login_failed|10.0.0.1"

	// Exhaust the limit.
	rl.Allow(key)
	rl.Allow(key)
	if rl.Allow(key) {
		t.Fatal("expected rate limit hit")
	}

	// Advance past the window.
	advance(61 * time.Second)

	if !rl.Allow(key) {
		t.Fatal("expected Allow() after window reset")
	}
}

func TestEventRateLimiter_DifferentKeysIndependent(t *testing.T) {
	t.Parallel()

	now := time.Now()
	clock := func() time.Time { return now }
	rl := newEventRateLimiter(2, time.Minute, 5*time.Minute, clock)
	defer rl.Stop()

	keyA := "auth.login_failed|10.0.0.1"
	keyB := "auth.login_failed|10.0.0.2"

	// Exhaust key A.
	rl.Allow(keyA)
	rl.Allow(keyA)
	if rl.Allow(keyA) {
		t.Fatal("key A should be rate limited")
	}

	// Key B should still be allowed.
	if !rl.Allow(keyB) {
		t.Fatal("key B should not be rate limited")
	}
}

func TestEventRateLimiter_TTLEviction(t *testing.T) {
	t.Parallel()

	mu := sync.Mutex{}
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	// Short TTL and window for testing. Eviction runs every ttl/2 = 50ms.
	rl := newEventRateLimiter(1, 100*time.Millisecond, 100*time.Millisecond, clock)
	defer rl.Stop()

	// Add many keys.
	for i := 0; i < 1000; i++ {
		rl.Allow("key" + string(rune(i)))
	}

	// Advance time past TTL.
	mu.Lock()
	now = now.Add(200 * time.Millisecond)
	mu.Unlock()

	// Wait for eviction goroutine to run.
	time.Sleep(200 * time.Millisecond)

	rl.mu.Lock()
	remaining := len(rl.buckets)
	rl.mu.Unlock()

	if remaining > 100 {
		t.Errorf("expected most entries evicted, got %d remaining", remaining)
	}
}

func TestEventRateLimiter_Stop(t *testing.T) {
	t.Parallel()

	rl := newEventRateLimiter(10, time.Minute, time.Minute, nil)
	rl.Stop()

	// Verify the done channel is closed (non-blocking receive succeeds).
	select {
	case <-rl.done:
		// Expected.
	default:
		t.Fatal("done channel not closed after Stop()")
	}
}
