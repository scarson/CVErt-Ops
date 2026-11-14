// ABOUTME: Compiles a validated alert DSL Rule into a CompiledRule with squirrel SQL predicates.
// ABOUTME: Regex conditions become PostFilters; watchlist IDs are appended as an EXISTS subquery.
package dsl

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// Compile converts a validated Rule into a CompiledRule ready for the evaluator.
// watchlistIDs (if non-empty) are appended as an additional AND EXISTS pre-filter.
// The caller must call Validate before Compile.
func Compile(r Rule, ruleID uuid.UUID, dslVersion int, orgID uuid.UUID, watchlistIDs []uuid.UUID) (*CompiledRule, error) {
	// Validate refuses this at save; a stored rule past the limit fails closed here.
	if len(r.Conditions) > maxConditions {
		return nil, fmt.Errorf("compile: %s", msgTooManyConditions)
	}
	if tooManyAndSets(r) {
		return nil, fmt.Errorf("compile: %s", msgTooManyAndSets)
	}
	if orMixesRegex(r) {
		return nil, fmt.Errorf("compile: %s", msgOrRegexMixed)
	}

	var predicates []predicate
	var postFilters []PostFilter
	hasEPSSCond := false
	allEPSS := true
	products := 0 // affected.cpe_product values, counted as Validate counts them

	// Under "or" every package eq and in condition shares one package branch.
	r, err := mergeOrPackageNames(r)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	corr, err := correlationFor(r)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	for _, c := range r.Conditions {
		spec, ok := fields[c.Field]
		if !ok {
			return nil, fmt.Errorf("compile: unknown field %q", c.Field)
		}
		// Validate refuses this at save; a stored rule with an operator its field
		// does not take fails closed here instead of compiling as another operator.
		if !containsStr(spec.validOps, c.Op) {
			return nil, fmt.Errorf("compile: condition %q: "+msgInvalidOperator, c.Field, c.Op, c.Field)
		}

		if c.Field == "epss_score" {
			hasEPSSCond = true
		} else {
			allEPSS = false
		}

		if spec.kind == kindProduct {
			// Compile re-applies Validate's value checks and product limit, so a
			// stored rule that fails them fails closed (design section 5.2). A
			// product set is never correlated with package conditions (section 4.2).
			refs, err := compileProducts(c)
			if err != nil {
				return nil, fmt.Errorf("compile: condition %q %s: %w", c.Field, c.Op, err)
			}
			products += len(refs)
			predicates = append(predicates, predicate{branches: productSet(refs), products: refs})
			continue
		}

		if c.Op == "regex" {
			re, err := compileRegex(c.Value)
			if err != nil {
				return nil, fmt.Errorf("compile: regex compile: %w", err)
			}
			postFilters = append(postFilters, PostFilter{Field: c.Field, Negate: false, Pattern: re})
			continue
		}

		if spec.kind == kindAffected {
			// A CVE-ID set, correlated under "and" (design section 4.2); an
			// ecosystem condition folded into the rule's package sets adds nothing.
			p, ok, err := affectedPredicate(c, corr)
			if err != nil {
				return nil, fmt.Errorf("compile: condition %q %s: %w", c.Field, c.Op, err)
			}
			if ok {
				predicates = append(predicates, p)
			}
			continue
		}

		sqlizer, err := conditionToSQL(c, spec)
		if err != nil {
			return nil, fmt.Errorf("compile: condition %q %s: %w", c.Field, c.Op, err)
		}
		predicates = append(predicates, predicate{scalar: sqlizer})
	}
	if products > maxProducts {
		return nil, fmt.Errorf("compile: %s", msgTooManyProducts)
	}
	orProducts := orProductArrays(r.Logic, predicates)

	var watchlist sq.Sqlizer
	if len(watchlistIDs) > 0 {
		watchlist = watchlistExpr(watchlistIDs, orgID)
	}
	if len(predicates) > 0 {
		// CompiledRule.Where combines the predicates by Logic.
		if r.Logic != LogicAnd && r.Logic != LogicOr {
			return nil, fmt.Errorf("compile: unknown logic %q", r.Logic)
		}
	} else if watchlist == nil {
		// All conditions are regex PostFilters.
		return nil, fmt.Errorf("compile: all conditions are regex with no watchlist IDs; add selective conditions")
	}

	var joins []string
	for _, c := range r.Conditions {
		if c.Field == "fts_query" {
			joins = append(joins, "cve_search_index si ON cves.cve_id = si.cve_id")
			break // only one FTS join needed
		}
	}

	isEPSSOnly := hasEPSSCond && allEPSS && len(r.Conditions) > 0
	return &CompiledRule{
		RuleID:       ruleID,
		DSLVersion:   dslVersion,
		predicates:   predicates,
		orProducts:   orProducts,
		watchlist:    watchlist,
		Joins:        joins,
		PostFilters:  postFilters,
		Logic:        r.Logic,
		IsEPSSOnly:   isEPSSOnly,
		HasEPSS:      hasEPSSCond,
		HasWatchlist: len(watchlistIDs) > 0,
	}, nil
}

// orProductArrays returns, for an "or" rule with product conditions, the
// bound arrays of every product condition's values together, in rule order;
// otherwise nil. A CVE in any product set is in the set of all their values,
// because each value's names and other products keep their own group, so
// CompiledRule.Where matches every product condition of an "or" rule with
// candidate IDs through one CPE and one CNA branch.
func orProductArrays(logic Logic, predicates []predicate) *productArrays {
	if logic != LogicOr {
		return nil
	}
	var values []check.ProductRef
	for _, p := range predicates {
		values = append(values, p.products...)
	}
	if len(values) == 0 {
		return nil
	}
	a := newProductArrays(values)
	return &a
}

// compileProducts returns an affected.cpe_product condition's values, parsed,
// normalised and de-duplicated by productValues. It refuses what Validate
// refuses: an operator other than eq or in, a value the parser refuses, and an
// empty list.
func compileProducts(c Condition) ([]check.ProductRef, error) {
	if c.Op != "eq" && c.Op != "in" {
		return nil, fmt.Errorf(msgInvalidOperator, c.Op, c.Field)
	}
	refs, refused, err := productValues(c)
	if err != nil {
		return nil, err
	}
	if refused != nil {
		return nil, refused
	}
	if len(refs) == 0 {
		return nil, errors.New(msgEmptyList)
	}
	return refs, nil
}

// watchlistExpr builds the EXISTS subquery that restricts results to CVEs matching at least
// one item in the given watchlists. orgID is embedded explicitly because worker transactions
// use bypass_rls and do not rely on app.org_id being set.
//
// Each item type has its own EXISTS so the planner can use that type's partial index. A
// watchlist can hold thousands of CVE items, and one EXISTS with an OR across the types
// would scan all of them for every candidate CVE.
//
// A package item's ecosystem matches a stored ecosystem that equals it or starts with it
// followed by a colon, so "Debian" covers every Debian release.
func watchlistExpr(watchlistIDs []uuid.UUID, orgID uuid.UUID) sq.Sqlizer {
	ids := pq.Array(watchlistIDs)
	return sq.Expr(`(
    EXISTS (
        SELECT 1 FROM watchlist_items wi
        WHERE wi.watchlist_id = ANY(?)
          AND wi.org_id       = ?
          AND wi.item_type    = 'cve'
          AND wi.deleted_at IS NULL
          AND wi.cve_id       = cves.cve_id
    )
    OR EXISTS (
        SELECT 1 FROM watchlist_items wi
        JOIN cve_affected_packages cap
          ON `+WatchlistPackageMatchSQL("cap", "wi")+`
        WHERE wi.watchlist_id = ANY(?)
          AND wi.org_id       = ?
          AND wi.item_type    = 'package'
          AND wi.deleted_at IS NULL
          AND cap.cve_id      = cves.cve_id
    )
    OR EXISTS (
        SELECT 1 FROM watchlist_items wi
        JOIN cve_affected_cpes cac
          ON `+WatchlistCPEMatchSQL("cac", "wi")+`
        WHERE wi.watchlist_id = ANY(?)
          AND wi.org_id       = ?
          AND wi.item_type    = 'cpe'
          AND wi.deleted_at IS NULL
          AND cac.cve_id      = cves.cve_id
    )
)`, ids, orgID, ids, orgID, ids, orgID)
}

// WatchlistPackageMatchSQL is the condition under which the cve_affected_packages row
// aliased pkg matches the package watchlist item aliased item: the stored ecosystem equals
// the item's or starts with it followed by a colon, and the names are equal once folded
// by the stored ecosystem's rule. Rule evaluation and the alert-event listing both use it,
// so an event's listed matches are the items that make the rule fire.
func WatchlistPackageMatchSQL(pkg, item string) string {
	return `(lower(` + pkg + `.ecosystem) = lower(` + item + `.ecosystem)
              OR starts_with(lower(` + pkg + `.ecosystem), lower(` + item + `.ecosystem) || ':'))
         AND ` + ecosystem.FoldedNameSQL(pkg+".ecosystem", pkg+".package_name") +
		` = ` + ecosystem.FoldedNameSQL(pkg+".ecosystem", item+".package_name")
}

// WatchlistCPEMatchSQL is the condition under which the cve_affected_cpes row aliased
// cpe matches the CPE watchlist item aliased item: the item is a prefix of the stored CPE.
func WatchlistCPEMatchSQL(cpe, item string) string {
	return cpe + `.cpe_normalized LIKE (` + item + `.cpe_normalized || '%')`
}

// conditionToSQL converts a single validated Condition to a squirrel Sqlizer.
func conditionToSQL(c Condition, spec fieldSpec) (sq.Sqlizer, error) {
	switch spec.kind {
	case kindFloat:
		return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
			var v float64
			if err := decodeScalar(raw, &v); err != nil {
				return nil, err
			}
			return v, nil
		})
	case kindTime:
		return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
			var s string
			if err := decodeScalar(raw, &s); err != nil {
				return nil, err
			}
			return time.Parse(time.RFC3339, s)
		})
	case kindBool:
		var v bool
		if err := decodeScalar(c.Value, &v); err != nil {
			return nil, fmt.Errorf("bool value: %w", err)
		}
		return sq.Eq{spec.sqlExpr: v}, nil
	case kindString, kindEnum:
		canon := func(v string) string { return v }
		if c.Field == "cve_id" {
			canon = canonicalCVEID
		}
		return setSQL(spec.sqlExpr, c.Op, c.Value, canon)
	case kindStrArray:
		var vals []string
		if err := json.Unmarshal(c.Value, &vals); err != nil {
			return nil, fmt.Errorf("array value: %w", err)
		}
		switch c.Op {
		case "contains_any":
			return sq.Expr(spec.sqlExpr+" && ?", pq.Array(vals)), nil
		case "contains_all":
			return sq.Expr(spec.sqlExpr+" @> ?", pq.Array(vals)), nil
		default:
			return nil, fmt.Errorf("unsupported op %q for strArray", c.Op)
		}
	case kindText:
		return textSQL(spec.sqlExpr, c.Op, c.Value)
	case kindFTS:
		var s string
		if err := decodeScalar(c.Value, &s); err != nil {
			return nil, fmt.Errorf("condition %q: value must be a string", c.Field)
		}
		return sq.Expr("si.fts_document @@ websearch_to_tsquery('english', ?)", s), nil
	default:
		return nil, fmt.Errorf("unsupported field kind %d", spec.kind)
	}
}

func numericSQL(sqlExpr, op string, raw json.RawMessage, parse func(json.RawMessage) (interface{}, error)) (sq.Sqlizer, error) {
	v, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("numeric value: %w", err)
	}
	switch op {
	case "gt":
		return sq.Gt{sqlExpr: v}, nil
	case "gte":
		return sq.GtOrEq{sqlExpr: v}, nil
	case "lt":
		return sq.Lt{sqlExpr: v}, nil
	case "lte":
		return sq.LtOrEq{sqlExpr: v}, nil
	case "eq":
		return sq.Eq{sqlExpr: v}, nil
	case "neq":
		return sq.NotEq{sqlExpr: v}, nil
	default:
		return nil, fmt.Errorf("unsupported numeric op %q", op)
	}
}

// cveIDPattern matches a CVE ID in any case. Stored CVE IDs are upper case;
// other stored identifiers, such as GHSA IDs, are mixed case.
var cveIDPattern = regexp.MustCompile(`(?i)^cve-\d{4}-\d+$`)

// canonicalCVEID returns v in upper case when it is a CVE ID, so a rule that
// writes "cve-2024-1234" matches the stored "CVE-2024-1234". Any other value is
// returned as written.
func canonicalCVEID(v string) string {
	if cveIDPattern.MatchString(v) {
		return strings.ToUpper(v)
	}
	return v
}

// setSQL builds eq/neq as one bound value and in/not_in as one bound array
// (pitfall DB-12: one placeholder per list value can pass PostgreSQL's 65,535
// parameter limit), each value passed through canon first. sqlExpr is a field
// registry constant, never user input.
func setSQL(sqlExpr, op string, raw json.RawMessage, canon func(string) string) (sq.Sqlizer, error) {
	if op == "in" || op == "not_in" {
		var vals []string
		if err := json.Unmarshal(raw, &vals); err != nil {
			return nil, fmt.Errorf("array value: %w", err)
		}
		// A JSON null list unmarshals to nil, and pq.Array(nil) binds SQL NULL:
		// <> ALL(NULL) is NULL, so not_in null would match nothing. An empty array
		// gives false for = ANY and true for <> ALL.
		if vals == nil {
			vals = []string{}
		}
		for i, v := range vals {
			vals[i] = canon(v)
		}
		if op == "in" {
			return sq.Expr(sqlExpr+" = ANY(?)", pq.Array(vals)), nil
		}
		return sq.Expr(sqlExpr+" <> ALL(?)", pq.Array(vals)), nil
	}
	var v string
	if err := decodeScalar(raw, &v); err != nil {
		return nil, fmt.Errorf("string value: %w", err)
	}
	v = canon(v)
	if op == "eq" {
		return sq.Eq{sqlExpr: v}, nil
	}
	return sq.NotEq{sqlExpr: v}, nil
}

// escapeLike escapes ILIKE metacharacters (%, _, \) so they are treated as
// literal characters in PostgreSQL ILIKE patterns.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func textSQL(sqlExpr, op string, raw json.RawMessage) (sq.Sqlizer, error) {
	var v string
	if err := decodeScalar(raw, &v); err != nil {
		return nil, fmt.Errorf("text value: %w", err)
	}
	escaped := escapeLike(strings.ToLower(v))
	switch op {
	case "contains":
		return sq.ILike{sqlExpr: "%" + escaped + "%"}, nil
	case "starts_with":
		return sq.ILike{sqlExpr: escaped + "%"}, nil
	case "ends_with":
		return sq.ILike{sqlExpr: "%" + escaped}, nil
	default:
		return nil, fmt.Errorf("unsupported text op %q", op)
	}
}
