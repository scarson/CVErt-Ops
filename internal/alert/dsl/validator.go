// ABOUTME: Semantic validation of a parsed alert DSL Rule.
// ABOUTME: Returns all validation errors at once so callers can display the full problem list.
package dsl

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// selectiveFields are non-regex fields that provide meaningful filtering,
// used to determine whether a regex-only rule is allowed without watchlists.
var selectiveFields = map[string]bool{
	"severity":                 true,
	"in_cisa_kev":              true,
	"date_published":           true,
	"date_modified_source_max": true,
	"affected.ecosystem":       true,
	"affected.package":         true,
}

// Validate performs semantic validation of a Rule. All errors are collected and returned together
// so the caller can display the full problem list. hasWatchlists relaxes the regex-only guard.
//
// Returns:
//   - errs: all ValidationError items found (check Severity == "error" before saving)
//   - hasEPSS: true if any condition references epss_score
//   - isEPSSOnly: true if ALL conditions reference epss_score
func Validate(r Rule, hasWatchlists bool) (errs []ValidationError, hasEPSS, isEPSSOnly bool) {
	hasEPSSCond := false
	allEPSS := true
	hasRegex := false
	hasSelective := false

	for i, c := range r.Conditions {
		spec, ok := fields[c.Field]
		if !ok {
			errs = append(errs, ValidationError{
				Index:    i,
				Field:    c.Field,
				Message:  fmt.Sprintf("unknown field %q", c.Field),
				Severity: "error",
			})
			allEPSS = false
			continue
		}

		if c.Field == "epss_score" {
			hasEPSSCond = true
		} else {
			allEPSS = false
		}

		if selectiveFields[c.Field] && c.Op != "regex" {
			hasSelective = true
		}

		if !containsStr(spec.validOps, c.Op) {
			errs = append(errs, ValidationError{
				Index:    i,
				Field:    c.Field,
				Message:  fmt.Sprintf("operator %q is not valid for field %q", c.Op, c.Field),
				Severity: "error",
			})
			continue
		}

		errs = append(errs, validateValue(i, c, spec)...)

		if c.Op == "regex" {
			hasRegex = true
			var pattern string
			if err := json.Unmarshal(c.Value, &pattern); err == nil && len(pattern) > 256 {
				errs = append(errs, ValidationError{
					Index:    i,
					Field:    c.Field,
					Message:  "regex pattern must not exceed 256 characters",
					Severity: "error",
				})
			}
		}

		if c.Op == "contains" {
			var pattern string
			if err := json.Unmarshal(c.Value, &pattern); err == nil && len(pattern) < 3 {
				errs = append(errs, ValidationError{
					Index:    i,
					Field:    c.Field,
					Message:  "contains pattern shorter than 3 characters may be slow (trigram index won't help)",
					Severity: "warning",
				})
			}
		}
	}

	if hasRegex && !hasSelective && !hasWatchlists {
		errs = append(errs, ValidationError{
			Index:    -1,
			Field:    "",
			Message:  "regex-only rule must have at least one selective non-regex condition or watchlist IDs assigned",
			Severity: "error",
		})
	}

	isEPSSOnly = hasEPSSCond && allEPSS && len(r.Conditions) > 0
	hasEPSS = hasEPSSCond
	return errs, hasEPSS, isEPSSOnly
}

// validateValue checks that c.Value is parseable and, for enums, is in the valid set.
func validateValue(idx int, c Condition, spec fieldSpec) []ValidationError {
	var errs []ValidationError
	add := func(msg string) {
		errs = append(errs, ValidationError{Index: idx, Field: c.Field, Message: msg, Severity: "error"})
	}

	switch spec.kind {
	case kindFloat:
		var v float64
		if err := json.Unmarshal(c.Value, &v); err != nil {
			add(fmt.Sprintf("value must be a number: %v", err))
		}

	case kindTime:
		var s string
		if err := json.Unmarshal(c.Value, &s); err != nil {
			add(fmt.Sprintf("value must be a JSON string: %v", err))
		} else if _, err := time.Parse(time.RFC3339, s); err != nil {
			add(fmt.Sprintf("value must be RFC 3339 time: %v", err))
		}

	case kindBool:
		var v bool
		if err := json.Unmarshal(c.Value, &v); err != nil {
			add(fmt.Sprintf("value must be a JSON boolean: %v", err))
		}

	case kindString, kindEnum:
		if c.Op == "in" || c.Op == "not_in" {
			var vals []string
			if err := json.Unmarshal(c.Value, &vals); err != nil {
				add(fmt.Sprintf("value must be a JSON array of strings: %v", err))
				return errs
			}
			if spec.kind == kindEnum {
				for _, v := range vals {
					if !containsStr(spec.enumValues, v) {
						add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
					}
				}
			}
		} else {
			var v string
			if err := json.Unmarshal(c.Value, &v); err != nil {
				add(fmt.Sprintf("value must be a JSON string: %v", err))
				return errs
			}
			if spec.kind == kindEnum && !containsStr(spec.enumValues, v) {
				add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
			}
		}

	case kindStrArray:
		var vals []string
		if err := json.Unmarshal(c.Value, &vals); err != nil {
			add(fmt.Sprintf("value must be a JSON array of strings: %v", err))
		}

	case kindText:
		if c.Op == "regex" {
			var pattern string
			if err := json.Unmarshal(c.Value, &pattern); err != nil {
				add(fmt.Sprintf("regex value must be a JSON string: %v", err))
			} else if _, err := regexp.Compile(pattern); err != nil {
				add(fmt.Sprintf("invalid regex: %v", err))
			}
		} else {
			var v string
			if err := json.Unmarshal(c.Value, &v); err != nil {
				add(fmt.Sprintf("value must be a JSON string: %v", err))
			}
		}

	case kindAffected:
		if c.Op == "in" || c.Op == "not_in" {
			var vals []string
			if err := json.Unmarshal(c.Value, &vals); err != nil {
				add(fmt.Sprintf("value must be a JSON array of strings: %v", err))
				return errs
			}
			if spec.enumValues != nil {
				for _, v := range vals {
					if !containsStr(spec.enumValues, v) {
						add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
					}
				}
			}
		} else {
			var v string
			if err := json.Unmarshal(c.Value, &v); err != nil {
				add(fmt.Sprintf("value must be a JSON string: %v", err))
				return errs
			}
			if spec.enumValues != nil && !containsStr(spec.enumValues, v) {
				add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
			}
		}
	}
	return errs
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
