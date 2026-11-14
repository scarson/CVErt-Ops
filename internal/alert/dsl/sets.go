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

// isPackageName reports whether c is an affected.package condition that compares
// whole names (eq or in), not substrings.
func isPackageName(c Condition) bool {
	return c.Field == "affected.package" && (c.Op == "eq" || c.Op == "in")
}

// mergeOrPackageNames returns r with, under "or", every affected.package eq and
// in condition replaced by one in condition holding all their values, in rule
// order, where the first of them stands. Under "or" package conditions are not
// correlated (design section 4.2), and a CVE has a row matching one of several
// names exactly when it has a row matching one of all of them, so the rule
// matches the same CVEs through one package branch, whose names packageMatch
// folds and de-duplicates per arm as for any in list. The candidate IDs and
// name arrays are then bound once, whatever the number of conditions. Under
// "and", or with no such condition, it returns r as it is. It never changes
// r.Conditions.
func mergeOrPackageNames(r Rule) (Rule, error) {
	if r.Logic != LogicOr {
		return r, nil
	}
	first := -1
	names := []string{}
	for i, c := range r.Conditions {
		if !isPackageName(c) {
			continue
		}
		vals, err := conditionValues(c)
		if err != nil {
			return Rule{}, fmt.Errorf("condition %q %s: %w", c.Field, c.Op, err)
		}
		if first < 0 {
			first = i
		}
		names = append(names, vals...)
	}
	if first < 0 {
		return r, nil
	}
	value, err := json.Marshal(names)
	if err != nil {
		return Rule{}, fmt.Errorf("package names: %w", err)
	}
	conds := make([]Condition, 0, len(r.Conditions))
	for i, c := range r.Conditions {
		switch {
		case i == first:
			conds = append(conds, Condition{Field: "affected.package", Op: "in", Value: value})
		case isPackageName(c):
			// Its values are in the merged condition.
		default:
			conds = append(conds, c)
		}
	}
	return Rule{Logic: r.Logic, Conditions: conds}, nil
}

// affectedPredicate compiles an affected.ecosystem or affected.package condition.
// It returns ok false for an eq/in ecosystem condition that corr folds into the
// rule's package sets.
func affectedPredicate(c Condition, corr packageCorrelation) (p predicate, ok bool, err error) {
	switch c.Field {
	case "affected.ecosystem":
		vals, err := conditionValues(c)
		if err != nil {
			return predicate{}, false, err
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
			return predicate{scalar: notExists}, true, nil
		case "eq", "in":
			if corr.active {
				return predicate{}, false, nil
			}
			lines := []sqlPart{line}
			return predicate{branches: func(candidateIDs []string) []sqlPart {
				return []sqlPart{packageBranch(candidateIDs, lines)}
			}}, true, nil
		default:
			return predicate{}, false, fmt.Errorf("unsupported ecosystem op %q", c.Op)
		}
	case "affected.package":
		match, err := packageMatch(c, corr)
		if err != nil {
			return predicate{}, false, err
		}
		lines := append(slices.Clone(corr.lines), match)
		return predicate{branches: func(candidateIDs []string) []sqlPart {
			return []sqlPart{packageBranch(candidateIDs, lines)}
		}}, true, nil
	default:
		return predicate{}, false, fmt.Errorf("unknown affected field %q", c.Field)
	}
}

// cveSet is the predicate that cves.cve_id is in the union of branches, each a
// SELECT of one cve_id column. It never changes branches or their args. With no
// branches it is FALSE.
func cveSet(branches []sqlPart) sq.Sqlizer {
	if len(branches) == 0 {
		return sq.Expr("FALSE")
	}
	sqls := make([]string, 0, len(branches))
	var args []any
	for _, b := range branches {
		sqls = append(sqls, b.sql)
		args = append(args, b.args...)
	}
	return sq.Expr(`cves.cve_id IN (
    `+strings.Join(sqls, "\n    UNION ALL\n    ")+`
)`, args...)
}

// packageBranch selects the IDs of CVEs with one cve_affected_packages row that
// meets every line. With candidate IDs, it reads only their rows. It reads lines
// and candidateIDs and never changes them, because the compiled rule that holds
// lines is shared across goroutines.
func packageBranch(candidateIDs []string, lines []sqlPart) sqlPart {
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
	return sqlPart{
		sql:  "SELECT cap.cve_id FROM cve_affected_packages cap\n    WHERE " + strings.Join(conds, "\n      AND "),
		args: args,
	}
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
		if err := decodeScalar(c.Value, &v); err != nil {
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
// products. With candidate IDs it is the bound-array form (productArrays);
// without, the range form (productBranches). values must not be empty; with
// none it returns FALSE.
func ProductSetSQL(values []check.ProductRef, candidateIDs []string) sq.Sqlizer {
	if len(values) == 0 {
		return sq.Expr("FALSE")
	}
	return cveSet(productSet(values)(candidateIDs))
}

// productSet returns the branches of one product set for given candidate IDs:
// the bound-array form when there are any, the range form when there are none.
// The arrays are built once, here; the closure only reads them and values, so
// the compiled rule that holds it can be shared across goroutines.
func productSet(values []check.ProductRef) func(candidateIDs []string) []sqlPart {
	arrays := newProductArrays(values)
	return func(candidateIDs []string) []sqlPart {
		if len(candidateIDs) > 0 {
			return arrays.branches(candidateIDs)
		}
		return productBranches(values)
	}
}

// productBranches are the range form's two SELECT branches, NVD then CNA, over
// the whole corpus. values must not be empty.
//
// Ranges and names are OR-ed predicates, not joins to unnest() arrays, so the
// planner reads cve_cpe_matches_check_idx and cve_cna_affected_check_idx
// (pitfall DB-27). Every range, name and other product is a bind argument.
func productBranches(values []check.ProductRef) []sqlPart {
	nvd := []sqlPart{{sql: "m.vulnerable"}, anyOf(cpeRanges(values))}
	groups := make([]sqlPart, 0, len(values))
	for _, v := range values {
		groups = append(groups, cnaNameGroup(v))
	}
	cna := []sqlPart{anyOf(groups)}

	nvdWhere, nvdArgs := allOf(nvd)
	cnaWhere, cnaArgs := allOf(cna)
	return []sqlPart{
		{sql: "SELECT m.cve_id FROM cve_cpe_matches m\n    WHERE " + nvdWhere, args: nvdArgs},
		{sql: "SELECT a.cve_id FROM cve_cna_affected a\n    WHERE " + cnaWhere, args: cnaArgs},
	}
}

// cpePrefixes returns the CPE prefix of each CPE spelling of each value and
// each part, each listed once, in value, spelling and part order.
func cpePrefixes(values []check.ProductRef) []string {
	var prefixes []string
	seen := map[string]bool{}
	for _, v := range values {
		_, cpes, _ := check.NamesFor(v)
		for _, cpe := range cpes {
			for _, part := range productParts {
				p := check.CPEKeyFor("cpe:2.3:" + part + ":" + cpe + ":").Prefix
				if seen[p] {
					continue
				}
				seen[p] = true
				prefixes = append(prefixes, p)
			}
		}
	}
	return prefixes
}

// cpeRanges returns one range term per prefix of cpePrefixes: a range on the
// index expression of cve_cpe_matches_check_idx with the whole prefix rechecked
// by starts_with (check.CPEKey).
func cpeRanges(values []check.ProductRef) []sqlPart {
	expr := check.CPEIndexExpr("m.cpe_normalized")
	prefixes := cpePrefixes(values)
	ranges := make([]sqlPart, 0, len(prefixes))
	for _, p := range prefixes {
		k := check.CPEKeyFor(p)
		ranges = append(ranges, sqlPart{
			sql:  "(" + expr + " >= ? AND " + expr + " < ? AND starts_with(m.cpe_normalized, ?))",
			args: []any{k.Lo, k.Hi, k.Prefix},
		})
	}
	return ranges
}

// productArrays are the bound-array form of a product set, used when the caller
// has candidate IDs: the branches reach rows through cve_id = ANY(candidates)
// and match them against arrays, so neither the SQL text nor the number of
// placeholders grows with the number of values, and planning time stays flat
// (dev/plans/2026-11-13-product-match-rules-measurements.md). The range form
// (productBranches) serves the whole corpus, where the check indexes must.
//
// Both forms match the same rows:
//
//   - A CPE prefix p matches cpe_normalized when it starts with p. The range
//     form's starts_with recheck decides this alone: a CPE starting with p has
//     first CPEKeyRunes characters starting with check.CPEKey.Lo, p cut to that
//     length, so it lies in [Lo, Hi) in the C collation.
//   - An exact name matches when lower(vendor) and lower(product) equal the
//     whole lower-cased names, which the range form rechecks and which imply its
//     comparisons of the first 256 characters.
//   - A prefix name matches when lower(vendor) equals the whole vendor and
//     lower(product) starts with the prefix. The range form ranges on the first
//     256 characters of lower(product) from the prefix cut to 256 characters,
//     which is the same test while the prefix has at most 256 characters. Prefix
//     names come only from the name table (".net "), whose names are far
//     shorter; a rule value, at most 255 characters, gives only exact names.
//   - Other products exclude a row only from the names of the value they belong
//     to, by group number, with check.IsOtherProduct's word boundary, as
//     otherProductPart does per value.
//
// Groups number values from 0 in the order given. Compile builds the arrays
// once; branches only reads them.
type productArrays struct {
	prefixes []string // CPE prefixes, lower case as ProductRef holds them

	nameVendors  []string // lower-cased CNA vendor of each name
	nameProducts []string // lower-cased CNA product, or prefix, of each name
	namePrefixes []bool   // whether each name is a prefix
	nameGroups   []int64  // the value each name belongs to

	otherGroups   []int64  // the value each other product belongs to
	otherVendors  []string // lower-cased vendor of each other product
	otherProducts []string // lower-cased product, or prefix, of each other product
	otherPrefixes []bool   // whether each other product is a prefix
}

// newProductArrays builds the arrays of values. Every slice is non-nil, because
// pq.Array(nil) binds SQL NULL.
func newProductArrays(values []check.ProductRef) productArrays {
	a := productArrays{
		prefixes:    cpePrefixes(values),
		nameVendors: []string{}, nameProducts: []string{}, namePrefixes: []bool{}, nameGroups: []int64{},
		otherGroups: []int64{}, otherVendors: []string{}, otherProducts: []string{}, otherPrefixes: []bool{},
	}
	for g, v := range values {
		names, _, _ := check.NamesFor(v)
		for _, n := range names {
			a.nameVendors = append(a.nameVendors, strings.ToLower(n.Vendor))
			a.nameProducts = append(a.nameProducts, strings.ToLower(n.Product))
			a.namePrefixes = append(a.namePrefixes, n.Prefix)
			a.nameGroups = append(a.nameGroups, int64(g))
		}
		for _, o := range check.OtherProductsFor(v) {
			a.otherGroups = append(a.otherGroups, int64(g))
			a.otherVendors = append(a.otherVendors, strings.ToLower(o.Vendor))
			a.otherProducts = append(a.otherProducts, strings.ToLower(o.Product))
			a.otherPrefixes = append(a.otherPrefixes, o.Prefix)
		}
	}
	return a
}

// productCPEBranch selects the CVEs among the candidates with a vulnerable CPE
// match row under any of the bound prefixes; ^@ is starts_with.
const productCPEBranch = `SELECT m.cve_id FROM cve_cpe_matches m
    WHERE m.vulnerable
      AND m.cve_id = ANY(?)
      AND m.cpe_normalized ^@ ANY(?::text[])`

// productCNABranch selects the CVEs among the candidates with a CNA row that
// carries a bound name n and is none of the other products of n's value. The
// boundary test after a prefix other product is check.IsOtherProduct's, as in
// otherProductPart. A row matching several names appears once per name, which
// the CVE set's IN ignores.
const productCNABranch = `SELECT a.cve_id FROM cve_cna_affected a
    JOIN unnest(?::text[], ?::text[], ?::boolean[], ?::int[]) AS n(v, p, is_prefix, grp)
      ON lower(a.vendor) = n.v
     AND (lower(a.product) = n.p OR (n.is_prefix AND starts_with(lower(a.product), n.p)))
    WHERE a.cve_id = ANY(?)
      AND NOT EXISTS (
        SELECT 1 FROM unnest(?::int[], ?::text[], ?::text[], ?::boolean[]) AS o(grp, v, p, is_prefix)
        WHERE o.grp = n.grp
          AND lower(a.vendor) = o.v
          AND (lower(a.product) = o.p
            OR (o.is_prefix AND starts_with(lower(a.product), o.p)
              AND substr(lower(a.product), char_length(o.p) + 1) !~ '^[a-z0-9]'))
      )`

// branches returns the bound-array form's two branches, CPE then CNA, limited
// to candidateIDs, which must not be empty. It never changes a or candidateIDs.
func (a *productArrays) branches(candidateIDs []string) []sqlPart {
	candidates := pq.Array(candidateIDs)
	return []sqlPart{
		{sql: productCPEBranch, args: []any{candidates, pq.Array(a.prefixes)}},
		{sql: productCNABranch, args: []any{
			pq.Array(a.nameVendors), pq.Array(a.nameProducts), pq.Array(a.namePrefixes), pq.Array(a.nameGroups),
			candidates,
			pq.Array(a.otherGroups), pq.Array(a.otherVendors), pq.Array(a.otherProducts), pq.Array(a.otherPrefixes),
		}},
	}
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
// binds SQL NULL, and = ANY(NULL) and LIKE ANY(NULL) are NULL, not false. A JSON
// null eq/neq value is an error (decodeScalar).
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
	if err := decodeScalar(c.Value, &v); err != nil {
		return nil, fmt.Errorf("string value: %w", err)
	}
	return []string{v}, nil
}
