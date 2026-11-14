// ABOUTME: Semantic validation of a parsed alert DSL Rule.
// ABOUTME: Returns all validation errors at once so callers can display the full problem list.
package dsl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// narrowingOps lists, per field, the operators whose condition narrows the SQL
// candidates a regex post-filter runs on (PLAN.md §10.2), so that a regex rule
// with one needs no watchlist. Negative operators and an upper bound on a date
// keep nearly every CVE, so they are not listed. in_cisa_kev narrows only with
// the value true (narrowsCandidates).
var narrowingOps = map[string][]string{
	"severity":                 {"eq", "in"},
	"in_cisa_kev":              {"eq"},
	"date_published":           {"gt", "gte", "eq"},
	"date_modified_source_max": {"gt", "gte", "eq"},
	"affected.ecosystem":       {"eq", "in"},
	"affected.package":         packageOps,
	"affected.cpe_product":     {"eq", "in"},
	"fts_query":                ftsOps,
}

// narrowsCandidates reports whether c narrows the CVEs a regex rule's post-filter
// is checked on (narrowingOps).
func narrowsCandidates(c Condition) bool {
	if !slices.Contains(narrowingOps[c.Field], c.Op) {
		return false
	}
	if c.Field == "in_cisa_kev" {
		var v bool
		return decodeScalar(c.Value, &v) == nil && v
	}
	return true
}

// maxConditions bounds a rule's conditions, and with them the copies of the
// candidate IDs one statement carries (design section 3.2).
const maxConditions = 100

// maxProducts bounds a rule's affected.cpe_product values, each of which adds
// its own OR terms and bind parameters (design section 3.2). Values are counted
// per condition after normalisation and de-duplication, and the counts summed:
// each condition compiles to its own set with its own parameters, so the same
// product in two conditions counts twice.
const maxProducts = 50

// maxAndSets bounds the set conditions of an "and" rule (design section 17).
// Under "and" each set is its own IN, and planning time grows with them; realtime
// evaluates every organisation's rules on each changed CVE.
const maxAndSets = 10

// Messages that Validate and Compile share, verbatim from design sections 8 and 17.
const (
	msgTooManyConditions   = "a rule may hold at most 100 conditions"
	msgTooManyProducts     = "a rule may name at most 50 products in total"
	msgTooManyAndSets      = `an "and" rule may hold at most 10 product, package and ecosystem conditions; list more values in one "in" condition, or use an "or" rule`
	msgNeverMatches        = `every ecosystem condition must hold on the same package row, and no ecosystem satisfies all of them, so this rule can never match; use one "in" condition if any of them is enough`
	msgNoEcosystemFirst    = `without an ecosystem condition in an "and" rule, this match cannot narrow by ecosystem first and may be slow on PostgreSQL versions before 18`
	msgEmptyList           = "value must list at least one item"
	msgInvalidOperator     = "operator %q is not valid for field %q"
	msgRegexNeedsNarrowing = `a regex rule needs a condition that narrows the CVEs it is checked on (severity eq or in; in_cisa_kev eq true; date_published or date_modified_source_max gt, gte or eq; affected.ecosystem or affected.cpe_product eq or in; any affected.package condition; fts_query), or watchlist IDs`
	msgOrRegexMixed        = `an "or" rule cannot combine regex conditions with other conditions, because a regex is checked only on CVEs the other conditions match; put the regex conditions in a rule of their own`
	// The value and names are printable ASCII (check.ParseProductValue), so they
	// are quoted as written rather than with %q, which would double a backslash.
	// The vendor and product are each one or more quoted spellings (spellings).
	msgUnmappedProduct = `no other CNA spelling is known for "%s"; before NVD analyses a CVE, it matches only if the CNA record names vendor %s and product %s`
)

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

		if narrowsCandidates(c) {
			hasSelective = true
		}

		if !containsStr(spec.validOps, c.Op) {
			errs = append(errs, ValidationError{
				Index:    i,
				Field:    c.Field,
				Message:  fmt.Sprintf(msgInvalidOperator, c.Op, c.Field),
				Severity: "error",
			})
			continue
		}

		errs = append(errs, validateValue(i, c, spec)...)

		if c.Op == "regex" {
			hasRegex = true
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
			Message:  msgRegexNeedsNarrowing,
			Severity: "error",
		})
	}

	if len(r.Conditions) > maxConditions {
		errs = append(errs, ValidationError{Index: -1, Field: "", Message: msgTooManyConditions, Severity: "error"})
	} else {
		// The never-matching check costs values times conditions, and runs only
		// on valid ecosystem values, which are short; within the condition limit
		// that is linear in the request.
		errs = append(errs, validatePackageCorrelation(r)...)
	}
	errs = append(errs, validateProducts(r)...)
	if tooManyAndSets(r) {
		errs = append(errs, ValidationError{Index: -1, Field: "", Message: msgTooManyAndSets, Severity: "error"})
	}
	if orMixesRegex(r) {
		errs = append(errs, ValidationError{Index: -1, Field: "", Message: msgOrRegexMixed, Severity: "error"})
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

	// Every field that takes regex (cve_id, description_primary) checks its
	// pattern as Compile compiles it.
	if c.Op == "regex" {
		if _, err := compileRegex(c.Value); err != nil {
			add(err.Error())
		}
		return errs
	}

	switch spec.kind {
	case kindFloat:
		var v float64
		if err := decodeScalar(c.Value, &v); err != nil {
			add(fmt.Sprintf("value must be a number: %v", err))
		}

	case kindTime:
		var s string
		if err := decodeScalar(c.Value, &s); err != nil {
			add(fmt.Sprintf("value must be a JSON string: %v", err))
		} else if _, err := time.Parse(time.RFC3339, s); err != nil {
			add(fmt.Sprintf("value must be RFC 3339 time: %v", err))
		}

	case kindBool:
		var v bool
		if err := decodeScalar(c.Value, &v); err != nil {
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
			if err := decodeScalar(c.Value, &v); err != nil {
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
		var v string
		if err := decodeScalar(c.Value, &v); err != nil {
			add(fmt.Sprintf("value must be a JSON string: %v", err))
		}

	case kindFTS:
		var s string
		if err := decodeScalar(c.Value, &s); err != nil {
			errs = append(errs, ValidationError{Index: idx, Field: c.Field, Message: "value must be a string", Severity: "error"})
			return errs
		}
		if s == "" {
			errs = append(errs, ValidationError{Index: idx, Field: c.Field, Message: "FTS query must not be empty", Severity: "error"})
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
					if !affectedValueValid(c.Field, spec, v) {
						add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
					}
				}
			}
			// Existing fields keep accepting an empty in; a package list must name a package.
			if c.Field == "affected.package" {
				if len(vals) == 0 {
					add(msgEmptyList)
				} else if slices.ContainsFunc(vals, isBlank) {
					add("value must not be empty")
				}
			}
		} else {
			var v string
			if err := decodeScalar(c.Value, &v); err != nil {
				add(fmt.Sprintf("value must be a JSON string: %v", err))
				return errs
			}
			if spec.enumValues != nil && !affectedValueValid(c.Field, spec, v) {
				add(fmt.Sprintf("value %q is not valid for %q; valid: %v", v, c.Field, spec.enumValues))
			}
			if c.Field == "affected.package" && c.Op == "eq" && isBlank(v) {
				add("value must not be empty")
			}
		}

	case kindProduct:
		if c.Op == "in" {
			var vals []string
			if err := json.Unmarshal(c.Value, &vals); err != nil {
				add(fmt.Sprintf("value must be a JSON array of strings: %v", err))
				return errs
			}
			if len(vals) == 0 {
				add(msgEmptyList)
				return errs
			}
		} else {
			var v string
			if err := decodeScalar(c.Value, &v); err != nil {
				add(fmt.Sprintf("value must be a JSON string: %v", err))
				return errs
			}
		}
		// The value's JSON parsed above, so productValues returns no error.
		if _, refused, _ := productValues(c); refused != nil {
			add(refused.Error())
		}
	}
	return errs
}

// productValues reads an affected.cpe_product condition's value, eq's string or
// in's list. It returns the values check.ParseProductValue accepts, normalised
// and without duplicates, in first-seen order. At the first value the parser
// refuses it stops and returns only the parser's error for that value, so a
// condition gives at most one value error however many values it lists.
// Validate and Compile both count a condition's products as len(refs), so they
// apply the same limit.
func productValues(c Condition) (refs []check.ProductRef, refused error, err error) {
	raw, err := conditionValues(c)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[check.ProductRef]bool, len(raw))
	for _, v := range raw {
		p, perr := check.ParseProductValue(v)
		if perr != nil {
			return nil, perr, nil
		}
		if !seen[p] {
			seen[p] = true
			refs = append(refs, p)
		}
	}
	return refs, nil, nil
}

// validateProducts applies the rule-level product checks: the 50-product limit
// (maxProducts) and, for a rule within it, a warning for each product the name
// table does not map, which before NVD's analysis matches only a CNA record that
// spells it as the CPE does. Giving warnings only within the limit bounds them
// at 50 per rule. Value errors are validateValue's; a condition with a value
// that fails to parse is not counted.
func validateProducts(r Rule) []ValidationError {
	type productCondition struct {
		index int
		refs  []check.ProductRef
	}
	var conds []productCondition
	total := 0
	for i, c := range r.Conditions {
		if c.Field != "affected.cpe_product" || (c.Op != "eq" && c.Op != "in") {
			continue
		}
		refs, refused, err := productValues(c)
		if err != nil || refused != nil {
			continue // reported by validateValue
		}
		total += len(refs)
		conds = append(conds, productCondition{index: i, refs: refs})
	}
	if total > maxProducts {
		return []ValidationError{{Index: -1, Field: "", Message: msgTooManyProducts, Severity: "error"}}
	}
	var errs []ValidationError
	for _, pc := range conds {
		for _, p := range pc.refs {
			names, _, mapped := check.NamesFor(p)
			if mapped {
				continue
			}
			errs = append(errs, ValidationError{
				Index:    pc.index,
				Field:    "affected.cpe_product",
				Message:  fmt.Sprintf(msgUnmappedProduct, p.Vendor+":"+p.Product, spellings(names, vendorOf), spellings(names, productOf)),
				Severity: "warning",
			})
		}
	}
	return errs
}

func vendorOf(n check.CNAName) string  { return n.Vendor }
func productOf(n check.CNAName) string { return n.Product }

// spellings quotes the distinct values part takes across names, in their order,
// joined by "or": a CPE part with an unescaped "_" has two CNA spellings (with
// "_" read as a space, and kept), and any vendor spelling pairs with any product
// spelling. The names are printable ASCII, so they are quoted as written.
func spellings(names []check.CNAName, part func(check.CNAName) string) string {
	var out []string
	for _, n := range names {
		if s := `"` + part(n) + `"`; !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return strings.Join(out, " or ")
}

// tooManyAndSets reports whether r is an "and" rule with more than maxAndSets set
// conditions: every affected.cpe_product and affected.package condition, and every
// affected.ecosystem eq/in condition when the rule has no affected.package
// condition. Beside a package condition those ecosystem conditions are folded into
// the package sets and add no set of their own. An "or" rule is not limited,
// because its sets compile to one predicate.
func tooManyAndSets(r Rule) bool {
	if r.Logic != LogicAnd {
		return false
	}
	hasPackage := slices.ContainsFunc(r.Conditions, func(c Condition) bool { return c.Field == "affected.package" })
	sets := 0
	for _, c := range r.Conditions {
		switch {
		case c.Field == "affected.cpe_product", c.Field == "affected.package":
			sets++
		case c.Field == "affected.ecosystem" && (c.Op == "eq" || c.Op == "in") && !hasPackage:
			sets++
		}
	}
	return sets > maxAndSets
}

// orMixesRegex reports whether r is an "or" rule with a regex condition beside
// a condition of another operator. A regex runs in Go only on the CVEs the
// rule's SQL conditions select (PLAN.md §10.2), so under "or" a CVE that only
// the regex matches would never be checked, and a CVE that only a SQL
// condition matches would be dropped by the regex: the rule would read as
// "and". An "or" rule of regex conditions alone is evaluated correctly, on the
// CVEs its watchlist selects.
func orMixesRegex(r Rule) bool {
	if r.Logic != LogicOr {
		return false
	}
	isRegex := func(c Condition) bool { return c.Op == "regex" }
	isOther := func(c Condition) bool { return c.Op != "regex" }
	return slices.ContainsFunc(r.Conditions, isRegex) && slices.ContainsFunc(r.Conditions, isOther)
}

// isBlank reports whether v is empty or only whitespace.
func isBlank(v string) bool { return strings.TrimSpace(v) == "" }

// validatePackageCorrelation checks a rule's package conditions against its
// correlated ecosystem conditions, the eq/in affected.ecosystem conditions that
// an "and" rule's package conditions must hold with on one row (design section
// 4.2). Such a rule whose ecosystem conditions no ecosystem satisfies together
// can never match, and an exact package match with no ecosystem to narrow by
// first gets a warning.
func validatePackageCorrelation(r Rule) []ValidationError {
	var errs []ValidationError
	hasPackage := false
	var exactPackages []int // indexes of affected.package eq/in conditions
	ecosystemConds := 0
	var ecosystemValues [][]string // values of the parseable ecosystem conditions
	for i, c := range r.Conditions {
		switch {
		case c.Field == "affected.package":
			hasPackage = true
			if c.Op == "eq" || c.Op == "in" {
				exactPackages = append(exactPackages, i)
			}
		case c.Field == "affected.ecosystem" && (c.Op == "eq" || c.Op == "in"):
			ecosystemConds++
			// An unparseable or invalid value is already reported by validateValue,
			// and the never-matching check then does not run. Valid values are short
			// canonical names, which bounds the check's cost: an invalid value can be
			// a megabyte of colons, each of which the check would look up a prefix for.
			if vals, err := conditionValues(c); err == nil && !slices.ContainsFunc(vals, invalidEcosystem) {
				ecosystemValues = append(ecosystemValues, vals)
			}
		}
	}

	if r.Logic == LogicAnd && hasPackage && ecosystemConds >= 2 &&
		len(ecosystemValues) == ecosystemConds && !ecosystemsSatisfiable(ecosystemValues) {
		errs = append(errs, ValidationError{Index: -1, Field: "", Message: msgNeverMatches, Severity: "error"})
	}
	if r.Logic != LogicAnd || ecosystemConds == 0 {
		for _, i := range exactPackages {
			errs = append(errs, ValidationError{Index: i, Field: "affected.package", Message: msgNoEcosystemFirst, Severity: "warning"})
		}
	}
	return errs
}

// ecosystemsSatisfiable reports whether some stored ecosystem matches a value of
// every condition. A value v matches a stored ecosystem s when s equals v, or when
// v's base takes a suffix and s starts with v followed by a colon.
//
// Matches are colon-prefix cones, so if any stored ecosystem satisfies every
// condition, the longest of the values that match it is itself one. It is
// therefore enough to try each value w as the stored ecosystem. The values that
// can match w are w and its colon-prefixes, so each condition is checked with a
// few map lookups: the cost is the number of values times the number of
// conditions, which Validate runs only within the 100-condition limit, where
// comparing values pairwise would be quadratic in the values (a request can hold
// tens of thousands).
func ecosystemsSatisfiable(conds [][]string) bool {
	sets := make([]map[string]bool, len(conds))
	for i, vals := range conds {
		sets[i] = make(map[string]bool, len(vals))
		for _, v := range vals {
			sets[i][v] = true
		}
	}
	tried := make(map[string]bool)
	for _, vals := range conds {
		for _, w := range vals {
			if tried[w] {
				continue
			}
			tried[w] = true
			if matchedByEvery(sets, w) {
				return true
			}
		}
	}
	return false
}

// matchedByEvery reports whether every condition's value set holds a value that
// matches the stored ecosystem w: w itself, or, when w's base takes a suffix, a
// prefix of w that ends before one of its colons.
func matchedByEvery(sets []map[string]bool, w string) bool {
	base, _, _ := strings.Cut(w, ":")
	takesSuffix := ecosystem.TakesSuffix(base)
	for _, set := range sets {
		matched := set[w] || (takesSuffix && hasColonPrefixIn(set, w))
		if !matched {
			return false
		}
	}
	return true
}

// hasColonPrefixIn reports whether set holds a prefix of w that ends before one
// of w's colons.
func hasColonPrefixIn(set map[string]bool, w string) bool {
	for i := range len(w) {
		if w[i] == ':' && set[w[:i]] {
			return true
		}
	}
	return false
}

// invalidEcosystem reports whether v is not an allowed affected.ecosystem value.
func invalidEcosystem(v string) bool { return !ecosystem.Valid(v) }

// affectedValueValid reports whether v is allowed for a kindAffected field with an
// enum. affected.ecosystem also allows a suffix, so it cannot use the enum alone.
func affectedValueValid(field string, spec fieldSpec, v string) bool {
	if field == "affected.ecosystem" {
		return ecosystem.Valid(v)
	}
	return containsStr(spec.enumValues, v)
}

// decodeScalar unmarshals a condition's single value into v. It refuses JSON
// null, which json.Unmarshal accepts by leaving v at its zero value: without
// this, "cvss_v3_score gt null" would read as "gt 0" and "description_primary
// contains null" would match every CVE. Validate and Compile both decode
// single values through it, so a stored rule with a null value fails closed.
func decodeScalar(raw json.RawMessage, v any) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null is not allowed")
	}
	return json.Unmarshal(raw, v)
}

// maxRegexLength bounds a regex pattern as the rule writes it (PLAN.md §10.2).
const maxRegexLength = 256

// compileRegex reads a regex condition's pattern and compiles it to match
// regardless of case, as PLAN.md §10.2 requires. "(?i)" goes before the
// pattern, so flags the pattern sets itself, such as "(?-i)", override it.
// The pattern is first compiled as written, so an error quotes only what the
// rule wrote. Validate and Compile both call it, so they accept the same
// patterns.
func compileRegex(raw json.RawMessage) (*regexp.Regexp, error) {
	var pattern string
	if err := decodeScalar(raw, &pattern); err != nil {
		return nil, fmt.Errorf("regex value must be a JSON string: %w", err)
	}
	if len(pattern) > maxRegexLength {
		return nil, errors.New("regex pattern must not exceed 256 characters")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex: %w", err)
	}
	return re, nil
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
