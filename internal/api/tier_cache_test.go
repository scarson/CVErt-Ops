// ABOUTME: Unit tests for the org tier in-memory cache.
// ABOUTME: Verifies TTL expiration, invalidation, and idle eviction.
package api

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTierCache_HitAndMiss(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	c := newTierCache(clock, 30*time.Second, 5*time.Minute)
	defer c.Stop()

	orgID := uuid.New()

	// Miss on empty cache.
	_, _, ok := c.Get(orgID)
	if ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Set and hit.
	overrides := map[string]any{"max_alert_rules": float64(10)}
	c.Set(orgID, "pro", overrides)

	tier, ovr, ok := c.Get(orgID)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if tier != "pro" {
		t.Errorf("tier = %q, want pro", tier)
	}
	if v, exists := ovr["max_alert_rules"]; !exists || v != float64(10) {
		t.Errorf("overrides = %v, want max_alert_rules=10", ovr)
	}
}

func TestTierCache_TTLExpiry(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	c := newTierCache(clock, 30*time.Second, 5*time.Minute)
	defer c.Stop()

	orgID := uuid.New()
	c.Set(orgID, "free", nil)

	// Still valid at 29s.
	now = now.Add(29 * time.Second)
	_, _, ok := c.Get(orgID)
	if !ok {
		t.Fatal("expected hit at 29s (within TTL)")
	}

	// Expired at 31s.
	now = now.Add(2 * time.Second)
	_, _, ok = c.Get(orgID)
	if ok {
		t.Fatal("expected miss at 31s (past TTL)")
	}
}

func TestTierCache_Invalidate(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	c := newTierCache(clock, 30*time.Second, 5*time.Minute)
	defer c.Stop()

	orgID := uuid.New()
	c.Set(orgID, "free", nil)

	_, _, ok := c.Get(orgID)
	if !ok {
		t.Fatal("expected hit before invalidation")
	}

	c.Invalidate(orgID)

	_, _, ok = c.Get(orgID)
	if ok {
		t.Fatal("expected miss after invalidation")
	}
}

func TestTierCache_OverridesAreCopied(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	c := newTierCache(clock, 30*time.Second, 5*time.Minute)
	defer c.Stop()

	orgID := uuid.New()
	original := json.RawMessage(`{"max_alert_rules": 10}`)
	var overrides map[string]any
	_ = json.Unmarshal(original, &overrides)

	c.Set(orgID, "free", overrides)

	// Mutate the original map.
	overrides["injected"] = true

	// Cache should not reflect the mutation.
	_, cached, ok := c.Get(orgID)
	if !ok {
		t.Fatal("expected hit")
	}
	if _, exists := cached["injected"]; exists {
		t.Fatal("cache returned reference to caller's map — must copy on Set")
	}
}
