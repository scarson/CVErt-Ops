// ABOUTME: Parses a JSON alert DSL payload into a Rule IR.
// ABOUTME: Only structural validation is performed here; semantic checks are in validator.go.
package dsl

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// UnknownKeyError reports a key that the DSL does not define, in the rule object
// or in one of its conditions.
type UnknownKeyError struct {
	Index int    // index of the condition holding the key; -1 for a key of the rule object
	Key   string // the key as the payload spells it
}

func (e *UnknownKeyError) Error() string {
	if e.Index < 0 {
		return fmt.Sprintf("dsl: unknown key %q", e.Key)
	}
	return fmt.Sprintf("dsl: unknown key %q in conditions[%d]", e.Key, e.Index)
}

// Parse unmarshals a JSON DSL payload into a Rule. It checks only structural validity:
// the rule and each condition hold only the keys the DSL defines (an
// *UnknownKeyError otherwise, matched case-sensitively), logic must be "and" or
// "or", and conditions must be non-empty. A condition's value is kept as raw
// JSON. Call Validate for semantic checks (field names, operators, value types).
func Parse(data []byte) (Rule, error) {
	var r Rule
	if err := jsonv2.Unmarshal(data, &r, jsonv2.RejectUnknownMembers(true)); err != nil {
		if semErr, ok := errors.AsType[*jsonv2.SemanticError](err); ok && errors.Is(semErr.Err, jsonv2.ErrUnknownName) {
			return Rule{}, unknownKeyError(semErr.JSONPointer)
		}
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

// unknownKeyError locates the unknown key at ptr. Because condition values are
// raw JSON, an unknown key is either a member of the rule object (/key) or a
// member of a condition (/conditions/<index>/key).
func unknownKeyError(ptr jsontext.Pointer) *UnknownKeyError {
	parents := slices.Collect(ptr.Parent().Tokens())
	if len(parents) == 2 && parents[0] == "conditions" {
		if i, err := strconv.Atoi(parents[1]); err == nil {
			return &UnknownKeyError{Index: i, Key: ptr.LastToken()}
		}
	}
	return &UnknownKeyError{Index: -1, Key: ptr.LastToken()}
}
