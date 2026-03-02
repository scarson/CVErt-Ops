// ABOUTME: In-memory cache for org tier and overrides, keyed by org UUID.
// ABOUTME: Short TTL avoids per-request DB round-trip; invalidated on tier writes.
package api

import (
	"maps"
	"sync"
	"time"

	"github.com/google/uuid"
)

type tierCacheEntry struct {
	tier      string
	overrides map[string]any
	fetchedAt time.Time
}

type tierCache struct {
	mu       sync.Mutex
	entries  map[uuid.UUID]*tierCacheEntry
	ttl      time.Duration
	evictTTL time.Duration
	now      func() time.Time
	done     chan struct{}
}

func newTierCache(now func() time.Time, ttl, evictTTL time.Duration) *tierCache {
	c := &tierCache{
		entries:  make(map[uuid.UUID]*tierCacheEntry),
		ttl:      ttl,
		evictTTL: evictTTL,
		now:      now,
		done:     make(chan struct{}),
	}
	go c.cleanupLoop()
	return c
}

// Stop terminates the background cleanup goroutine.
func (c *tierCache) Stop() {
	close(c.done)
}

// Get returns cached tier data if present and not expired.
func (c *tierCache) Get(orgID uuid.UUID) (string, map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.entries[orgID]
	if !ok {
		return "", nil, false
	}
	if c.now().Sub(e.fetchedAt) > c.ttl {
		delete(c.entries, orgID)
		return "", nil, false
	}
	return e.tier, maps.Clone(e.overrides), true
}

// Set stores tier data in the cache, copying the overrides map.
// NOTE: maps.Clone is a shallow copy — safe because override values are scalars
// (float64, bool). If nested structures are added, switch to a deep copy.
func (c *tierCache) Set(orgID uuid.UUID, tier string, overrides map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[orgID] = &tierCacheEntry{
		tier:      tier,
		overrides: maps.Clone(overrides),
		fetchedAt: c.now(),
	}
}

// Invalidate removes a single org's entry from the cache.
func (c *tierCache) Invalidate(orgID uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, orgID)
}

// cleanupLoop evicts entries older than evictTTL. The ticker fires at evictTTL/2
// so entries linger at most 1.5x evictTTL in memory; functionally they become
// invisible to Get after the shorter TTL.
func (c *tierCache) cleanupLoop() {
	ticker := time.NewTicker(c.evictTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.evictExpired()
		case <-c.done:
			return
		}
	}
}

func (c *tierCache) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := c.now().Add(-c.evictTTL)
	for id, e := range c.entries {
		if e.fetchedAt.Before(cutoff) {
			delete(c.entries, id)
		}
	}
}
