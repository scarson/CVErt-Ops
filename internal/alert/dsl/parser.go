// ABOUTME: Parses a JSON alert DSL payload into a Rule IR.
// ABOUTME: Only structural validation is performed here; semantic checks are in validator.go.
package dsl

import (
	"encoding/json"
	"fmt"
)

// Parse unmarshals a JSON DSL payload into a Rule. It checks only structural validity:
// logic must be "and" or "or", and conditions must be non-empty.
// Call Validate for semantic checks (field names, operators, value types).
func Parse(data []byte) (Rule, error) {
	var r Rule
	if err := json.Unmarshal(data, &r); err != nil {
		return Rule{}, fmt.Errorf("dsl: invalid JSON: %w", err)
	}
	if r.Logic != LogicAnd && r.Logic != LogicOr {
		return Rule{}, fmt.Errorf("dsl: logic must be %q or %q, got %q", LogicAnd, LogicOr, r.Logic)
	}
	if len(r.Conditions) == 0 {
		return Rule{}, fmt.Errorf("dsl: conditions must be non-empty")
	}
	return r, nil
}
