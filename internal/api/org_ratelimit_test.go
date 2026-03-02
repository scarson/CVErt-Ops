// ABOUTME: Tests for per-org API rate limiter with tier-aware rate support.
// ABOUTME: Uses package api (not api_test) to access unexported types.
package api

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

func TestOrgRateLimiter_Allow(t *testing.T) {
	t.Parallel()
	now := time.Now()
	lim := newOrgRateLimiter(func() time.Time { return now }, 5*time.Minute)

	orgA := uuid.New()
	// Allow at burst=10.
	for i := 0; i < 10; i++ {
		if !lim.Allow(orgA, rate.Limit(10), 10) {
			t.Errorf("request %d: should be allowed (within burst of 10)", i)
		}
	}
	if lim.Allow(orgA, rate.Limit(10), 10) {
		t.Error("11th request: should be denied (burst exhausted)")
	}
}

func TestOrgRateLimiter_DifferentOrgs(t *testing.T) {
	t.Parallel()
	now := time.Now()
	lim := newOrgRateLimiter(func() time.Time { return now }, 5*time.Minute)

	orgA := uuid.New()
	orgB := uuid.New()

	// Exhaust org A.
	for i := 0; i < 5; i++ {
		lim.Allow(orgA, rate.Limit(10), 5)
	}
	if lim.Allow(orgA, rate.Limit(10), 5) {
		t.Error("org A: should be denied")
	}

	// Org B should still be allowed.
	if !lim.Allow(orgB, rate.Limit(10), 5) {
		t.Error("org B: should be allowed (independent bucket)")
	}
}

func TestOrgRateLimiter_RateChange(t *testing.T) {
	t.Parallel()
	now := time.Now()
	lim := newOrgRateLimiter(func() time.Time { return now }, 5*time.Minute)

	orgA := uuid.New()

	// Start with burst=2.
	lim.Allow(orgA, rate.Limit(10), 2)
	lim.Allow(orgA, rate.Limit(10), 2)
	if lim.Allow(orgA, rate.Limit(10), 2) {
		t.Error("should be denied at burst=2")
	}

	// Tier upgrade: burst=10 with different rate → new limiter created.
	if !lim.Allow(orgA, rate.Limit(20), 10) {
		t.Error("should be allowed after rate change (new limiter)")
	}
}

func TestOrgRateLimiter_Eviction(t *testing.T) {
	t.Parallel()
	now := time.Now()
	evictTTL := 5 * time.Minute
	lim := newOrgRateLimiter(func() time.Time { return now }, evictTTL)

	orgA := uuid.New()
	lim.Allow(orgA, rate.Limit(10), 10)

	// Advance past eviction TTL.
	now = now.Add(evictTTL + time.Second)
	lim.evictIdle()

	// After eviction, org A should get a fresh limiter (full burst).
	for i := 0; i < 10; i++ {
		if !lim.Allow(orgA, rate.Limit(10), 10) {
			t.Errorf("post-eviction request %d: should be allowed (fresh limiter)", i)
		}
	}
}
