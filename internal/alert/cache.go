// ABOUTME: In-memory compiled rule cache for the alert evaluator.
// ABOUTME: Thread-safe; keyed by (rule_id, dsl_version); entries evicted on rule update or delete.
package alert

import (
	"sync"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

type cacheKey struct {
	ruleID     uuid.UUID
	dslVersion int
}

// RuleCache caches compiled DSL rules to avoid recompiling on each evaluation.
// Cache entries are evicted on rule update or delete. No TTL.
type RuleCache struct {
	mu    sync.RWMutex
	rules map[cacheKey]*dsl.CompiledRule
}

// NewRuleCache returns an empty rule cache.
func NewRuleCache() *RuleCache {
	return &RuleCache{rules: make(map[cacheKey]*dsl.CompiledRule)}
}

// Get returns the compiled rule for (ruleID, dslVersion), or (nil, false) if not cached.
func (c *RuleCache) Get(ruleID uuid.UUID, dslVersion int) (*dsl.CompiledRule, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.rules[cacheKey{ruleID, dslVersion}]
	return r, ok
}

// Set stores a compiled rule in the cache.
func (c *RuleCache) Set(ruleID uuid.UUID, dslVersion int, rule *dsl.CompiledRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[cacheKey{ruleID, dslVersion}] = rule
}

// Evict removes all cached versions of ruleID. Call on rule update or delete.
func (c *RuleCache) Evict(ruleID uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.rules {
		if k.ruleID == ruleID {
			delete(c.rules, k)
		}
	}
}
