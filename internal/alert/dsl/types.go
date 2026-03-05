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

// CompiledRule is the output of Compile, ready for the alert evaluator.
type CompiledRule struct {
	RuleID      uuid.UUID
	DSLVersion  int
	SQL         sq.Sqlizer   // WHERE predicate only; no LIMIT, no FROM
	Joins       []string     // optional JOINs (e.g., FTS cve_search_index)
	PostFilters []PostFilter // Go-side regex filters (description_primary only, MVP)
	Logic        Logic        // and/or — controls PostFilter combination semantics
	IsEPSSOnly   bool         // all conditions reference epss_score
	HasEPSS      bool         // any condition references epss_score
	HasWatchlist bool         // compiled SQL includes watchlist subquery (needs RLS bypass)
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
	Index    int    // condition index; -1 for rule-level errors
	Field    string
	Message  string
	Severity string // "error" (blocks save) | "warning" (advisory only)
}

func (e ValidationError) Error() string { return e.Message }
