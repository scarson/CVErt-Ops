// ABOUTME: IR types for the alert DSL: Rule, Condition, CompiledRule, PostFilter, ValidationError.
// ABOUTME: These types flow through Parse → Validate → Compile and into the alert evaluator.
package dsl

import (
	"encoding/json"
	"regexp"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
)

// Logic defines how conditions within a rule are combined.
type Logic string

// LogicAnd and LogicOr define how conditions within a rule are combined.
const (
	LogicAnd Logic = "and"
	LogicOr  Logic = "or"
)

// Rule is the top-level DSL IR produced by Parse. It is the input to Validate and Compile.
type Rule struct {
	Logic      Logic       `json:"logic"`
	Conditions []Condition `json:"conditions"`
}

// Condition is a single filter clause within a Rule.
type Condition struct {
	Field string          `json:"field"`
	Op    string          `json:"operator"`
	Value json.RawMessage `json:"value"`
}

// CompiledRule is the output of Compile, ready for the alert evaluator. The rule
// cache shares one CompiledRule across goroutines, so it is never mutated after
// Compile returns.
type CompiledRule struct {
	RuleID       uuid.UUID
	DSLVersion   int
	predicates   []predicate  // one per SQL condition, in rule order
	watchlist    sq.Sqlizer   // watchlist pre-filter; nil when the rule has no watchlists
	Joins        []string     // optional JOINs (e.g., FTS cve_search_index)
	PostFilters  []PostFilter // Go-side regex filters (description_primary only, MVP)
	Logic        Logic        // and/or — controls PostFilter combination semantics
	IsEPSSOnly   bool         // all conditions reference epss_score
	HasEPSS      bool         // any condition references epss_score
	HasWatchlist bool         // compiled SQL includes watchlist subquery (needs RLS bypass)
}

// predicate is one compiled condition: a scalar condition on the cves row, or a
// CVE-ID set given as its SELECT branches. Exactly one of scalar and branches is
// set. branches limits each branch to candidateIDs; nil or empty means the whole
// corpus. branches is a pure closure over values computed in Compile and must
// not mutate them.
type predicate struct {
	scalar   sq.Sqlizer
	branches func(candidateIDs []string) []sqlPart
}

// Where returns the rule's WHERE predicate (no FROM, no LIMIT): its conditions
// combined by Logic, and the watchlist pre-filter ANDed on when the rule has one.
// It returns nil for a rule with neither. A set condition repeats candidateIDs
// inside each of its branches (pitfall DB-27); callers that have candidate IDs
// also filter cves.cve_id on them themselves.
//
// Under "and" each set condition is its own cves.cve_id IN predicate, which
// PostgreSQL plans as a semi-join. Under "or" the branches of every set condition
// form one IN predicate, placed where the first set condition is: PostgreSQL
// cannot turn OR-ed IN subqueries into semi-joins and builds each as a hashed
// SubPlan over its whole set, which one IN over a UNION ALL avoids.
func (c *CompiledRule) Where(candidateIDs []string) sq.Sqlizer {
	if len(c.predicates) == 0 {
		// All conditions are regex PostFilters; Compile requires a watchlist then.
		return c.watchlist
	}
	// Compile refuses any logic other than and/or.
	if c.Logic == LogicOr {
		parts := make([]sq.Sqlizer, 0, len(c.predicates))
		setAt := -1
		var branches []sqlPart
		for _, p := range c.predicates {
			if p.branches == nil {
				parts = append(parts, p.scalar)
				continue
			}
			if setAt < 0 {
				setAt = len(parts)
				parts = append(parts, nil)
			}
			branches = append(branches, p.branches(candidateIDs)...)
		}
		if setAt >= 0 {
			parts[setAt] = cveSet(branches)
		}
		if c.watchlist != nil {
			return sq.And{sq.Or(parts), c.watchlist}
		}
		return sq.Or(parts)
	}
	parts := make([]sq.Sqlizer, len(c.predicates))
	for i, p := range c.predicates {
		if p.branches == nil {
			parts[i] = p.scalar
			continue
		}
		parts[i] = cveSet(p.branches(candidateIDs))
	}
	if c.watchlist != nil {
		return append(sq.And(parts), c.watchlist)
	}
	return sq.And(parts)
}

// PostFilter is an in-process regex filter applied to SQL result set candidates.
// Field identifies which candidate field to match against (e.g., "description_primary", "cve_id").
type PostFilter struct {
	Field   string // DSL field name (e.g., "description_primary", "cve_id")
	Negate  bool
	Pattern *regexp.Regexp
}

// ValidationError describes a single validation problem.
// Multiple errors may be returned together so callers see the full problem list.
type ValidationError struct {
	Index    int // condition index; -1 for rule-level errors
	Field    string
	Message  string
	Severity string // "error" (blocks save) | "warning" (advisory only)
}

func (e ValidationError) Error() string { return e.Message }
