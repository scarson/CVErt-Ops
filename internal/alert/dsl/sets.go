// ABOUTME: Builds the CVE-ID set predicates for child-table conditions.
// ABOUTME: Each set repeats the caller's candidate IDs inside its branches (pitfall DB-27).
package dsl

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// sqlPart is a fixed SQL fragment and its bind values. Values are never
// concatenated into sql; only column expressions and fixed text are.
type sqlPart struct {
	sql  string
	args []any
}

// packageCorrelation is what an "and" rule's package conditions must hold
// together with on one cve_affected_packages row (design section 4.2): every
// affected.ecosystem condition that uses eq or in.
type packageCorrelation struct {
	// active is set for an "and" rule with at least one package condition. Its
	// eq/in ecosystem conditions then emit nothing on their own, because every
	// package set already carries their lines.
	active     bool
	lines      []sqlPart // one ecosystem line per correlated ecosystem condition
	ecosystems []string  // the values of every correlated ecosystem condition
}

// correlationFor collects the correlated ecosystem conditions of an "and" rule.
// Under "or" every condition matches on its own, so it returns no correlation.
func correlationFor(r Rule) (packageCorrelation, error) {
	var corr packageCorrelation
	if r.Logic != LogicAnd {
		return corr, nil
	}
	for _, c := range r.Conditions {
		switch {
		case c.Field == "affected.package":
			corr.active = true
		case c.Field == "affected.ecosystem" && (c.Op == "eq" || c.Op == "in"):
			vals, err := conditionValues(c)
			if err != nil {
				return packageCorrelation{}, fmt.Errorf("condition %q %s: %w", c.Field, c.Op, err)
			}
			corr.lines = append(corr.lines, ecosystemLine(vals))
			corr.ecosystems = append(corr.ecosystems, vals...)
		}
	}
	return corr, nil
}

// affectedPredicate compiles an affected.ecosystem or affected.package condition.
// It returns a nil predicate for an eq/in ecosystem condition that corr folds
// into the rule's package sets.
func affectedPredicate(c Condition, corr packageCorrelation) (predicate, error) {
	switch c.Field {
	case "affected.ecosystem":
		vals, err := conditionValues(c)
		if err != nil {
			return nil, err
		}
		line := ecosystemLine(vals)
		switch c.Op {
		case "neq", "not_in":
			// Read per row, a negative condition would mean "some row in another
			// ecosystem"; it stays "no row in this ecosystem", as a correlated
			// NOT EXISTS (a NOT IN over a large set is slow, pitfall DB-27).
			notExists := sq.Expr(`NOT EXISTS (
    SELECT 1 FROM cve_affected_packages cap
    WHERE cap.cve_id = cves.cve_id
      AND `+line.sql+`
)`, line.args...)
			return func(_ []string) sq.Sqlizer { return notExists }, nil
		case "eq", "in":
			if corr.active {
				return nil, nil
			}
			lines := []sqlPart{line}
			return func(candidateIDs []string) sq.Sqlizer { return packageSet(candidateIDs, lines) }, nil
		default:
			return nil, fmt.Errorf("unsupported ecosystem op %q", c.Op)
		}
	case "affected.package":
		match, err := packageMatch(c, corr)
		if err != nil {
			return nil, err
		}
		lines := append(slices.Clone(corr.lines), match)
		return func(candidateIDs []string) sq.Sqlizer { return packageSet(candidateIDs, lines) }, nil
	default:
		return nil, fmt.Errorf("unknown affected field %q", c.Field)
	}
}

// packageSet is the set of CVE IDs with one cve_affected_packages row that meets
// every line. With candidate IDs, the set reads only their rows. It reads lines
// and candidateIDs and never changes them, because the compiled rule that holds
// lines is shared across goroutines.
func packageSet(candidateIDs []string, lines []sqlPart) sq.Sqlizer {
	conds := make([]string, 0, len(lines)+1)
	args := make([]any, 0, len(lines)+2)
	if len(candidateIDs) > 0 {
		conds = append(conds, "cap.cve_id = ANY(?)")
		args = append(args, pq.Array(candidateIDs))
	}
	for _, l := range lines {
		conds = append(conds, l.sql)
		args = append(args, l.args...)
	}
	return sq.Expr(`cves.cve_id IN (
    SELECT cap.cve_id FROM cve_affected_packages cap
    WHERE `+strings.Join(conds, "\n      AND ")+`
)`, args...)
}

// ecosystemLine matches a stored ecosystem that equals one of vals, compared
// exactly, or that starts with a value followed by a colon when the value's base
// takes a suffix, so "Debian" covers every Debian release and "Ubuntu:22.04"
// covers "Ubuntu:22.04:LTS". A line with no such value is a plain = ANY, which
// cve_affected_packages_check_idx serves.
func ecosystemLine(vals []string) sqlPart {
	var releases []string
	for _, v := range vals {
		base, _, _ := strings.Cut(v, ":")
		if ecosystem.TakesSuffix(base) {
			releases = append(releases, escapeLike(v)+":%")
		}
	}
	if len(releases) == 0 {
		return sqlPart{sql: "cap.ecosystem = ANY(?)", args: []any{pq.Array(vals)}}
	}
	return sqlPart{
		sql:  "(cap.ecosystem = ANY(?) OR cap.ecosystem LIKE ANY(?))",
		args: []any{pq.Array(vals), pq.Array(releases)},
	}
}

// packageMatch builds an affected.package condition's line. eq and in compare
// the row's name, folded for the row's ecosystem by the index expression, with
// the values folded in Go; the substring operators match the lower-cased name.
func packageMatch(c Condition, corr packageCorrelation) (sqlPart, error) {
	switch c.Op {
	case "eq", "in":
		vals, err := conditionValues(c)
		if err != nil {
			return sqlPart{}, err
		}
		folded := ecosystem.FoldedNameSQL("cap.ecosystem", "cap.package_name") + " = ANY(?)"
		pypiNames := foldedNames("PyPI", vals)
		// FoldPackageName folds every ecosystem but PyPI to lower case.
		otherNames := foldedNames("npm", vals)
		if len(corr.lines) > 0 {
			anyPyPI := slices.Contains(corr.ecosystems, "PyPI")
			allPyPI := anyPyPI && !slices.ContainsFunc(corr.ecosystems, func(e string) bool { return e != "PyPI" })
			if allPyPI {
				return sqlPart{sql: folded, args: []any{pq.Array(pypiNames)}}, nil
			}
			if !anyPyPI {
				return sqlPart{sql: folded, args: []any{pq.Array(otherNames)}}, nil
			}
		}
		// The row may be PyPI or not, so each arm compares names folded its way.
		return sqlPart{
			sql:  "((cap.ecosystem = 'PyPI' AND " + folded + ") OR (cap.ecosystem <> 'PyPI' AND " + folded + "))",
			args: []any{pq.Array(pypiNames), pq.Array(otherNames)},
		}, nil
	case "contains", "starts_with", "ends_with":
		var v string
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return sqlPart{}, fmt.Errorf("package value: %w", err)
		}
		escaped := escapeLike(strings.ToLower(v))
		var pattern string
		switch c.Op {
		case "contains":
			pattern = "%" + escaped + "%"
		case "starts_with":
			pattern = escaped + "%"
		default:
			pattern = "%" + escaped
		}
		return sqlPart{sql: "lower(cap.package_name) ILIKE ?", args: []any{pattern}}, nil
	default:
		return sqlPart{}, fmt.Errorf("unsupported package op %q", c.Op)
	}
}

// foldedNames folds each value as FoldPackageName does for eco, without duplicates,
// in first-seen order. A list can hold tens of thousands of names, so duplicates
// are found with a map, not by scanning the output.
func foldedNames(eco string, vals []string) []string {
	out := make([]string, 0, len(vals))
	seen := make(map[string]bool, len(vals))
	for _, v := range vals {
		if f := ecosystem.FoldPackageName(eco, v); !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	return out
}

// conditionValues returns an eq/neq condition's value, or an in/not_in
// condition's list. A JSON null list returns an empty list, not nil: pq.Array(nil)
// binds SQL NULL, and = ANY(NULL) and LIKE ANY(NULL) are NULL, not false.
func conditionValues(c Condition) ([]string, error) {
	if c.Op == "in" || c.Op == "not_in" {
		var vals []string
		if err := json.Unmarshal(c.Value, &vals); err != nil {
			return nil, fmt.Errorf("array value: %w", err)
		}
		if vals == nil {
			vals = []string{}
		}
		return vals, nil
	}
	var v string
	if err := json.Unmarshal(c.Value, &v); err != nil {
		return nil, fmt.Errorf("string value: %w", err)
	}
	return []string{v}, nil
}
