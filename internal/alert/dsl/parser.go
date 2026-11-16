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
	if err := jsonv2.Unmarshal(data, &r, decodeOptions); err != nil {
		return Rule{}, decodeError(err, "conditions")
	}
	if r.Logic != LogicAnd && r.Logic != LogicOr {
		return Rule{}, fmt.Errorf("dsl: logic must be %q or %q, got %q", LogicAnd, LogicOr, r.Logic)
	}
	if len(r.Conditions) == 0 {
		return Rule{}, fmt.Errorf("dsl: conditions must be non-empty")
	}
	return r, nil
}

// ParseConditions decodes a stored conditions array with the key rules Parse
// uses (an *UnknownKeyError for an undefined or case-variant key) and refuses
// an empty or null array or an element that is not an object. Logic is stored
// in its own column, which a CHECK constraint limits to "and" and "or". Like
// Parse, it checks no field names, operators or values; Compile checks those
// for a stored rule.
func ParseConditions(data []byte) ([]Condition, error) {
	// Pointer elements tell a null element, which v2 decodes into a struct as
	// its zero value, apart from an object.
	var elems []*Condition
	if err := jsonv2.Unmarshal(data, &elems, decodeOptions); err != nil {
		return nil, decodeError(err)
	}
	if len(elems) == 0 {
		return nil, fmt.Errorf("dsl: conditions must be non-empty")
	}
	conditions := make([]Condition, len(elems))
	for i, c := range elems {
		if c == nil {
			return nil, fmt.Errorf("dsl: conditions[%d] is not an object", i)
		}
		conditions[i] = *c
	}
	return conditions, nil
}

// decodeOptions are the options every DSL decode uses: encoding/json/v2's
// defaults plus refusal of keys the DSL does not define.
var decodeOptions = jsonv2.RejectUnknownMembers(true)

// decodeError converts an error from a decode with decodeOptions: an unknown
// key becomes an *UnknownKeyError located under conditionsPath (see
// unknownKeyError); any other error is reported as invalid JSON.
func decodeError(err error, conditionsPath ...string) error {
	if semErr, ok := errors.AsType[*jsonv2.SemanticError](err); ok && errors.Is(semErr.Err, jsonv2.ErrUnknownName) {
		return unknownKeyError(semErr.JSONPointer, conditionsPath)
	}
	return fmt.Errorf("dsl: invalid JSON: %w", err)
}

// unknownKeyError locates the unknown key at ptr. conditionsPath holds the
// pointer tokens of the conditions array: ["conditions"] in a rule object, none
// for a bare conditions array. Because condition values are raw JSON, an
// unknown key is either a member of a condition (<conditionsPath>/<index>/key)
// or, in a rule object, a member of the rule (/key).
func unknownKeyError(ptr jsontext.Pointer, conditionsPath []string) *UnknownKeyError {
	parents := slices.Collect(ptr.Parent().Tokens())
	if len(parents) == len(conditionsPath)+1 && slices.Equal(parents[:len(conditionsPath)], conditionsPath) {
		if i, err := strconv.Atoi(parents[len(conditionsPath)]); err == nil {
			return &UnknownKeyError{Index: i, Key: ptr.LastToken()}
		}
	}
	return &UnknownKeyError{Index: -1, Key: ptr.LastToken()}
}
