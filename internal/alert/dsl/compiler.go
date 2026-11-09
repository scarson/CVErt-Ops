// ABOUTME: Compiles a validated alert DSL Rule into a CompiledRule with squirrel SQL predicates.
// ABOUTME: Regex conditions become PostFilters; watchlist IDs are appended as an EXISTS subquery.
package dsl

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/ecosystem"
)

// Compile converts a validated Rule into a CompiledRule ready for the evaluator.
// watchlistIDs (if non-empty) are appended as an additional AND EXISTS pre-filter.
// The caller must call Validate before Compile.
func Compile(r Rule, ruleID uuid.UUID, dslVersion int, orgID uuid.UUID, watchlistIDs []uuid.UUID) (*CompiledRule, error) {
	var sqlParts []sq.Sqlizer
	var postFilters []PostFilter
	hasEPSSCond := false
	allEPSS := true

	for _, c := range r.Conditions {
		spec, ok := fields[c.Field]
		if !ok {
			return nil, fmt.Errorf("compile: unknown field %q", c.Field)
		}

		if c.Field == "epss_score" {
			hasEPSSCond = true
		} else {
			allEPSS = false
		}

		if c.Op == "regex" {
			var pattern string
			if err := json.Unmarshal(c.Value, &pattern); err != nil {
				return nil, fmt.Errorf("compile: regex value: %w", err)
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile: regex compile: %w", err)
			}
			postFilters = append(postFilters, PostFilter{Field: c.Field, Negate: false, Pattern: re})
			continue
		}

		sqlizer, err := conditionToSQL(c, spec)
		if err != nil {
			return nil, fmt.Errorf("compile: condition %q %s: %w", c.Field, c.Op, err)
		}
		sqlParts = append(sqlParts, sqlizer)
	}

	var combined sq.Sqlizer
	if len(sqlParts) > 0 {
		switch r.Logic {
		case LogicAnd:
			if len(watchlistIDs) > 0 {
				all := make(sq.And, len(sqlParts)+1)
				copy(all, sqlParts)
				all[len(sqlParts)] = watchlistExpr(watchlistIDs, orgID)
				combined = all
			} else {
				and := make(sq.And, len(sqlParts))
				copy(and, sqlParts)
				combined = and
			}
		case LogicOr:
			or := make(sq.Or, len(sqlParts))
			copy(or, sqlParts)
			if len(watchlistIDs) > 0 {
				combined = sq.And{or, watchlistExpr(watchlistIDs, orgID)}
			} else {
				combined = or
			}
		default:
			return nil, fmt.Errorf("compile: unknown logic %q", r.Logic)
		}
	} else {
		// All conditions are regex PostFilters.
		if len(watchlistIDs) > 0 {
			combined = watchlistExpr(watchlistIDs, orgID)
		} else {
			return nil, fmt.Errorf("compile: all conditions are regex with no watchlist IDs; add selective conditions")
		}
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
		SQL:          combined,
		Joins:        joins,
		PostFilters:  postFilters,
		Logic:        r.Logic,
		IsEPSSOnly:   isEPSSOnly,
		HasEPSS:      hasEPSSCond,
		HasWatchlist: len(watchlistIDs) > 0,
	}, nil
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
          ON (lower(cap.ecosystem) = lower(wi.ecosystem)
              OR starts_with(lower(cap.ecosystem), lower(wi.ecosystem) || ':'))
         AND `+ecosystem.FoldedNameSQL("cap.ecosystem", "cap.package_name")+` = `+ecosystem.FoldedNameSQL("cap.ecosystem", "wi.package_name")+`
        WHERE wi.watchlist_id = ANY(?)
          AND wi.org_id       = ?
          AND wi.item_type    = 'package'
          AND wi.deleted_at IS NULL
          AND cap.cve_id      = cves.cve_id
    )
    OR EXISTS (
        SELECT 1 FROM watchlist_items wi
        JOIN cve_affected_cpes cac
          ON cac.cpe_normalized LIKE (wi.cpe_normalized || '%')
        WHERE wi.watchlist_id = ANY(?)
          AND wi.org_id       = ?
          AND wi.item_type    = 'cpe'
          AND wi.deleted_at IS NULL
          AND cac.cve_id      = cves.cve_id
    )
)`, ids, orgID, ids, orgID, ids, orgID)
}

// conditionToSQL converts a single validated Condition to a squirrel Sqlizer.
func conditionToSQL(c Condition, spec fieldSpec) (sq.Sqlizer, error) {
	switch spec.kind {
	case kindFloat:
		return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
			var v float64
			if err := json.Unmarshal(raw, &v); err != nil {
				return nil, err
			}
			return v, nil
		})
	case kindTime:
		return numericSQL(spec.sqlExpr, c.Op, c.Value, func(raw json.RawMessage) (interface{}, error) {
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return nil, err
			}
			return time.Parse(time.RFC3339, s)
		})
	case kindBool:
		var v bool
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return nil, fmt.Errorf("bool value: %w", err)
		}
		return sq.Eq{spec.sqlExpr: v}, nil
	case kindString, kindEnum:
		return setSQL(spec.sqlExpr, c.Op, c.Value)
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
	case kindAffected:
		return affectedSQL(c)
	case kindFTS:
		var s string
		if err := json.Unmarshal(c.Value, &s); err != nil {
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

func setSQL(sqlExpr, op string, raw json.RawMessage) (sq.Sqlizer, error) {
	if op == "in" || op == "not_in" {
		var vals []string
		if err := json.Unmarshal(raw, &vals); err != nil {
			return nil, fmt.Errorf("array value: %w", err)
		}
		if op == "in" {
			return sq.Eq{sqlExpr: vals}, nil
		}
		return sq.NotEq{sqlExpr: vals}, nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("string value: %w", err)
	}
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
	if err := json.Unmarshal(raw, &v); err != nil {
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

func affectedSQL(c Condition) (sq.Sqlizer, error) {
	switch c.Field {
	case "affected.ecosystem":
		return affectedEcosystemSQL(c)
	case "affected.package":
		return affectedPackageSQL(c)
	default:
		return nil, fmt.Errorf("unknown affected field %q", c.Field)
	}
}

// affectedEcosystemSQL matches a stored ecosystem that equals a rule value or
// starts with it followed by a colon, so "Debian" covers every Debian release.
func affectedEcosystemSQL(c Condition) (sq.Sqlizer, error) {
	var vals []string
	if c.Op == "in" || c.Op == "not_in" {
		if err := json.Unmarshal(c.Value, &vals); err != nil {
			return nil, fmt.Errorf("ecosystem array value: %w", err)
		}
	} else {
		var v string
		if err := json.Unmarshal(c.Value, &v); err != nil {
			return nil, fmt.Errorf("ecosystem value: %w", err)
		}
		vals = []string{v}
	}

	patterns := make([]string, 0, len(vals)*2)
	for _, v := range vals {
		escaped := escapeLike(strings.ToLower(v))
		patterns = append(patterns, escaped, escaped+":%")
	}

	exists := `EXISTS (
    SELECT 1 FROM cve_affected_packages cap
    WHERE cap.cve_id = cves.cve_id
      AND lower(cap.ecosystem) LIKE ANY(?)
)`
	if c.Op == "neq" || c.Op == "not_in" {
		exists = "NOT " + exists
	}
	return sq.Expr(exists, pq.Array(patterns)), nil
}

func affectedPackageSQL(c Condition) (sq.Sqlizer, error) {
	var v string
	if err := json.Unmarshal(c.Value, &v); err != nil {
		return nil, fmt.Errorf("package value: %w", err)
	}
	escaped := escapeLike(strings.ToLower(v))
	var pattern string
	switch c.Op {
	case "contains":
		pattern = "%" + escaped + "%"
	case "starts_with":
		pattern = escaped + "%"
	case "ends_with":
		pattern = "%" + escaped
	default:
		return nil, fmt.Errorf("unsupported package op %q", c.Op)
	}
	return sq.Expr(`EXISTS (
    SELECT 1 FROM cve_affected_packages cap
    WHERE cap.cve_id = cves.cve_id
      AND lower(cap.package_name) ILIKE ?
)`, pattern), nil
}
