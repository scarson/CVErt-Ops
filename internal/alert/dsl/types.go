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
	PostFilters []PostFilter // Go-side regex filters (description_primary only, MVP)
	IsEPSSOnly  bool         // all conditions reference epss_score
	HasEPSS     bool         // any condition references epss_score
}

// PostFilter is an in-process regex filter applied to SQL result set candidates.
// Field is always description_primary in MVP.
type PostFilter struct {
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
