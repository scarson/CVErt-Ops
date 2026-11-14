// ABOUTME: Builds the CVE-ID set predicates for child-table conditions: packages, ecosystems and CPE products.
// ABOUTME: Each set repeats the caller's candidate IDs inside its branches (pitfall DB-27).
package dsl

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/check"
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

// productParts are the CPE parts a product value matches. A value names no
// part, so it matches all three (design section 3.2).
var productParts = []string{"a", "o", "h"}

// ProductSetSQL is the CVE-ID set for one affected.cpe_product condition
// (design section 5.1): NVD vulnerable CPE rows under any CPE spelling of any
// value, and CNA rows carrying any name of a value but none of its other
// products. candidateIDs is repeated inside both branches when non-empty.
//
// Ranges and names are OR-ed predicates, not joins to unnest() arrays, so the
// planner reads cve_cpe_matches_check_idx and cve_cna_affected_check_idx
// (pitfall DB-27). Every range, name and other product is a bind argument.
// values must not be empty; with none it returns FALSE.
func ProductSetSQL(values []check.ProductRef, candidateIDs []string) sq.Sqlizer {
	if len(values) == 0 {
		return sq.Expr("FALSE")
	}
	nvd := []sqlPart{{sql: "m.vulnerable"}}
	var cna []sqlPart
	if len(candidateIDs) > 0 {
		nvd = append(nvd, sqlPart{sql: "m.cve_id = ANY(?)", args: []any{pq.Array(candidateIDs)}})
		cna = append(cna, sqlPart{sql: "a.cve_id = ANY(?)", args: []any{pq.Array(candidateIDs)}})
	}
	nvd = append(nvd, anyOf(cpeRanges(values)))
	groups := make([]sqlPart, 0, len(values))
	for _, v := range values {
		groups = append(groups, cnaNameGroup(v))
	}
	cna = append(cna, anyOf(groups))

	nvdWhere, nvdArgs := allOf(nvd)
	cnaWhere, cnaArgs := allOf(cna)
	return sq.Expr(`cves.cve_id IN (
    SELECT m.cve_id FROM cve_cpe_matches m
    WHERE `+nvdWhere+`
    UNION ALL
    SELECT a.cve_id FROM cve_cna_affected a
    WHERE `+cnaWhere+`
)`, append(nvdArgs, cnaArgs...)...)
}

// cpeRanges returns one range term per CPE spelling of each value and per part,
// each listed once: a range on the index expression of cve_cpe_matches_check_idx
// with the whole prefix rechecked by starts_with (check.CPEKey).
func cpeRanges(values []check.ProductRef) []sqlPart {
	expr := check.CPEIndexExpr("m.cpe_normalized")
	var ranges []sqlPart
	seen := map[string]bool{}
	for _, v := range values {
		_, cpes, _ := check.NamesFor(v)
		for _, cpe := range cpes {
			for _, part := range productParts {
				k := check.CPEKeyFor("cpe:2.3:" + part + ":" + cpe + ":")
				if seen[k.Prefix] {
					continue
				}
				seen[k.Prefix] = true
				ranges = append(ranges, sqlPart{
					sql:  "(" + expr + " >= ? AND " + expr + " < ? AND starts_with(m.cpe_normalized, ?))",
					args: []any{k.Lo, k.Hi, k.Prefix},
				})
			}
		}
	}
	return ranges
}

// cnaNameGroup matches a CNA row that carries any CNA name of value v and, when
// v has other products, is none of them. The exclusion covers only v's group:
// a row that is another product of v can still be a name of another value.
func cnaNameGroup(v check.ProductRef) sqlPart {
	names, _, _ := check.NamesFor(v)
	terms := make([]sqlPart, 0, len(names))
	for _, n := range names {
		terms = append(terms, cnaNameTerm(check.CNANameKeyFor(n)))
	}
	group := anyOf(terms)
	others := check.OtherProductsFor(v)
	if len(others) == 0 {
		return group
	}
	not := otherProductPart("lower(a.vendor)", "lower(a.product)", others)
	return sqlPart{sql: "(" + group.sql + " AND NOT " + not.sql + ")", args: append(group.args, not.args...)}
}

// cnaNameTerm matches the CNA rows of one name key on the index expressions of
// cve_cna_affected_check_idx, then rechecks the whole lower-cased names, which
// the index cuts to 256 characters: vendor and product for an exact name, the
// vendor for a prefix name.
func cnaNameTerm(k check.CNANameKey) sqlPart {
	v, p := check.CNANameIndexExpr("a.vendor"), check.CNANameIndexExpr("a.product")
	if k.FullProduct != "" {
		return sqlPart{
			sql:  "(" + v + " = ? AND " + p + " = ? AND lower(a.vendor) = ? AND lower(a.product) = ?)",
			args: []any{k.V, k.Lo, k.FullVendor, k.FullProduct},
		}
	}
	return sqlPart{
		sql:  "(" + v + " = ? AND " + p + " >= ? AND " + p + " < ? AND lower(a.vendor) = ?)",
		args: []any{k.V, k.Lo, k.Hi, k.FullVendor},
	}
}

// OtherProductSQL is the condition, over the lower-cased vendor and product
// SQL expressions given, under which a CNA row is one of others: vendor equal,
// product equal, or for a prefix starting with it and followed by nothing or by
// a character that is not an ASCII letter or digit (check.IsOtherProduct's rule).
func OtherProductSQL(vendorExpr, productExpr string, others []check.CNAName) sq.Sqlizer {
	p := otherProductPart(vendorExpr, productExpr, others)
	return sq.Expr(p.sql, p.args...)
}

// otherProductPart builds OtherProductSQL's condition. Names are lower-cased,
// as check.CNAName.Matches compares them. A row reaching this test matched a
// name term, so its vendor and product are not NULL.
func otherProductPart(vendorExpr, productExpr string, others []check.CNAName) sqlPart {
	terms := make([]sqlPart, 0, len(others))
	for _, o := range others {
		vendor, product := strings.ToLower(o.Vendor), strings.ToLower(o.Product)
		if !o.Prefix {
			terms = append(terms, sqlPart{
				sql:  "(" + vendorExpr + " = ? AND " + productExpr + " = ?)",
				args: []any{vendor, product},
			})
			continue
		}
		terms = append(terms, sqlPart{
			sql: "(" + vendorExpr + " = ? AND starts_with(" + productExpr + ", ?) AND substr(" + productExpr +
				", char_length(?) + 1) !~ '^[a-z0-9]')",
			args: []any{vendor, product, product},
		})
	}
	return anyOf(terms)
}

// anyOf joins parts with OR inside parentheses.
func anyOf(parts []sqlPart) sqlPart {
	sqls := make([]string, 0, len(parts))
	var args []any
	for _, p := range parts {
		sqls = append(sqls, p.sql)
		args = append(args, p.args...)
	}
	return sqlPart{sql: "(" + strings.Join(sqls, "\n        OR ") + ")", args: args}
}

// allOf joins parts with AND, one per line, and returns the SQL and its args.
func allOf(parts []sqlPart) (string, []any) {
	sqls := make([]string, 0, len(parts))
	var args []any
	for _, p := range parts {
		sqls = append(sqls, p.sql)
		args = append(args, p.args...)
	}
	return strings.Join(sqls, "\n      AND "), args
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
