// ABOUTME: Tests that Compile refuses what Validate refuses in a condition: an operator the
// ABOUTME: field does not take and a JSON null value, so a stored rule fails closed.
package dsl_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

// severityCritical is a selective condition, so a rule with it and a regex
// condition passes the regex-only check without a watchlist.
const severityCritical = `{"field":"severity","operator":"eq","value":"critical"}`

// TestCompile_RefusesOperatorNotValidForField checks Compile fails closed on
// every operator the field registry does not list for a field (PLAN.md §10.5),
// as Validate does, instead of compiling it as some other operator.
func TestCompile_RefusesOperatorNotValidForField(t *testing.T) {
	t.Parallel()
	allOps := []string{
		"eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte",
		"contains", "starts_with", "ends_with", "regex",
		"contains_any", "contains_all", "matches",
	}
	listOps := map[string]bool{"in": true, "not_in": true, "contains_any": true, "contains_all": true}
	for _, fd := range dsl.ExportFieldDescriptions() {
		for _, op := range allOps {
			if slices.Contains(fd.ValidOps, op) {
				continue
			}
			value := `"x"`
			if listOps[op] {
				value = `["x"]`
			}
			r := dsl.Rule{Logic: dsl.LogicAnd, Conditions: []dsl.Condition{
				{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
				{Field: fd.Name, Op: op, Value: json.RawMessage(value)},
			}}
			want := fmt.Sprintf("operator %q is not valid for field %q", op, fd.Name)
			if errs, _, _ := dsl.Validate(r, false); len(findError(errs, want)) != 1 {
				t.Errorf("%s %s: Validate entries = %+v, want %q", fd.Name, op, errs, want)
			}
			_, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("%s %s: Compile error = %v, want %q", fd.Name, op, err, want)
			}
		}
	}
}

// TestCompile_RefusesStoredOperatorsSeenCompilingWrongly pins the stored rules
// the MATCH-2 review found compiling to other SQL: severity gte and contains
// read as neq, in_cisa_kev neq read as eq, and fts_query eq read as matches.
func TestCompile_RefusesStoredOperatorsSeenCompilingWrongly(t *testing.T) {
	t.Parallel()
	for _, c := range []dsl.Condition{
		{Field: "severity", Op: "gte", Value: json.RawMessage(`"high"`)},
		{Field: "severity", Op: "contains", Value: json.RawMessage(`"high"`)},
		{Field: "in_cisa_kev", Op: "neq", Value: json.RawMessage(`true`)},
		{Field: "fts_query", Op: "eq", Value: json.RawMessage(`"openssl"`)},
	} {
		r := dsl.Rule{Logic: dsl.LogicAnd, Conditions: []dsl.Condition{c}}
		if compiled, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil); err == nil {
			sql, _, _ := compiled.Where(nil).ToSql()
			t.Errorf("%s %s: compiled to %q, want an error", c.Field, c.Op, sql)
		}
	}
}

// TestValidateCompile_RefuseNullScalarValue checks a JSON null where a
// condition takes one value is refused by Validate and Compile. json.Unmarshal
// accepts null and leaves the zero value, so "cvss_v3_score gt null" read as
// "gt 0" and "description_primary contains null" matched every CVE.
func TestValidateCompile_RefuseNullScalarValue(t *testing.T) {
	t.Parallel()
	conds := []struct{ field, op string }{
		{"cvss_v3_score", "gt"},
		{"cvss_v4_score", "lte"},
		{"epss_score", "eq"},
		{"date_published", "gt"},
		{"in_cisa_kev", "eq"},
		{"exploit_available", "eq"},
		{"cve_id", "eq"},
		{"cve_id", "neq"},
		{"cve_id", "regex"},
		{"severity", "eq"},
		{"description_primary", "contains"},
		{"description_primary", "starts_with"},
		{"description_primary", "ends_with"},
		{"description_primary", "regex"},
		{"fts_query", "matches"},
		{"affected.ecosystem", "eq"},
		{"affected.package", "eq"},
		{"affected.package", "contains"},
		{"affected.cpe_product", "eq"},
	}
	for _, tc := range conds {
		r := mustParse(t, ruleJSON("and", severityCritical,
			`{"field":"`+tc.field+`","operator":"`+tc.op+`","value":null}`))
		errs, _, _ := dsl.Validate(r, false)
		if !slices.ContainsFunc(errs, func(e dsl.ValidationError) bool { return e.Index == 1 && e.Severity == "error" }) {
			t.Errorf("%s %s null: Validate entries = %+v, want an error on condition 1", tc.field, tc.op, errs)
		}
		if _, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil); err == nil {
			t.Errorf("%s %s null: Compile succeeded, want an error", tc.field, tc.op)
		}
	}
}
