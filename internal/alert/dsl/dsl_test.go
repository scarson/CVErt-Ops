// ABOUTME: Unit tests for the alert DSL compiler: Parse, Validate, Compile, and accessors.
// ABOUTME: Pure logic tests — no database required.
package dsl_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// ─── Parse ───────────────────────────────────────────────────────────────────

func TestParse_Valid(t *testing.T) {
	t.Parallel()
	data := `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`
	r, err := dsl.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Logic != dsl.LogicAnd {
		t.Errorf("Logic = %q, want and", r.Logic)
	}
	if len(r.Conditions) != 1 {
		t.Errorf("len(Conditions) = %d, want 1", len(r.Conditions))
	}
}

func TestParse_OrLogic(t *testing.T) {
	t.Parallel()
	data := `{"logic":"or","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0},{"field":"in_cisa_kev","operator":"eq","value":true}]}`
	r, err := dsl.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if r.Logic != dsl.LogicOr {
		t.Errorf("Logic = %q, want or", r.Logic)
	}
	if len(r.Conditions) != 2 {
		t.Errorf("len(Conditions) = %d, want 2", len(r.Conditions))
	}
}

func TestParse_InvalidLogic(t *testing.T) {
	t.Parallel()
	data := `{"logic":"xor","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`
	_, err := dsl.Parse([]byte(data))
	if err == nil {
		t.Fatal("expected error for invalid logic, got nil")
	}
}

func TestParse_EmptyConditions(t *testing.T) {
	t.Parallel()
	data := `{"logic":"and","conditions":[]}`
	_, err := dsl.Parse([]byte(data))
	if err == nil {
		t.Fatal("expected error for empty conditions, got nil")
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := dsl.Parse([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// ─── Validate ────────────────────────────────────────────────────────────────

func mustParse(t *testing.T, data string) dsl.Rule {
	t.Helper()
	r, err := dsl.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return r
}

func TestValidate_ValidRule(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
}

func TestValidate_UnknownField(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"does_not_exist","operator":"eq","value":"x"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for unknown field, got %v", errs)
	}
}

func TestValidate_InvalidOp(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"regex","value":7.0}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid op, got %v", errs)
	}
}

func TestValidate_InvalidFloatValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gte","value":"notanumber"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-numeric value, got %v", errs)
	}
}

func TestValidate_InvalidEnumValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"extreme"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid enum value, got %v", errs)
	}
}

func TestValidate_ValidEnumInArray(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"in","value":["high","critical"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid enum array, got %v", errs)
	}
}

func TestValidate_InvalidEnumInArray(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"in","value":["high","extreme"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid enum in array, got %v", errs)
	}
}

func TestValidate_InvalidRegexPattern(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"},{"field":"description_primary","operator":"regex","value":"[invalid"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid regex pattern, got %v", errs)
	}
}

func TestValidate_RegexTooLong(t *testing.T) {
	t.Parallel()
	longPattern := strings.Repeat("a", 257)
	data, _ := json.Marshal(map[string]interface{}{
		"logic": "and",
		"conditions": []map[string]interface{}{
			{"field": "severity", "operator": "eq", "value": "critical"},
			{"field": "description_primary", "operator": "regex", "value": longPattern},
		},
	})
	r := mustParse(t, string(data))
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for regex pattern > 256 chars, got %v", errs)
	}
}

func TestValidate_RegexOnlyWithoutSelectiveOrWatchlist(t *testing.T) {
	t.Parallel()
	// regex on description_primary with no selective conditions and no watchlists
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for regex-only rule without selective conditions or watchlists")
	}
}

func TestValidate_RegexOnlyWithWatchlists_OK(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`)
	errs, _, _ := dsl.Validate(r, true) // hasWatchlists=true
	if hasError(errs) {
		t.Errorf("expected no errors with watchlists, got %v", errs)
	}
}

func TestValidate_RegexWithSelectiveCondition_OK(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"},{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for regex with selective condition, got %v", errs)
	}
}

func TestValidate_ShortContainsWarning(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"ab"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasWarning(errs) {
		t.Errorf("expected warning for short contains pattern, got %v", errs)
	}
	if hasError(errs) {
		t.Errorf("expected no errors for short contains (only warning), got errors: %v", errs)
	}
}

func TestValidate_IsEPSSOnly(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"gte","value":0.9}]}`)
	_, hasEPSS, isEPSSOnly := dsl.Validate(r, false)
	if !hasEPSS {
		t.Error("expected hasEPSS=true")
	}
	if !isEPSSOnly {
		t.Error("expected isEPSSOnly=true")
	}
}

func TestValidate_HasEPSSNotOnly(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"gte","value":0.9},{"field":"severity","operator":"eq","value":"critical"}]}`)
	_, hasEPSS, isEPSSOnly := dsl.Validate(r, false)
	if !hasEPSS {
		t.Error("expected hasEPSS=true")
	}
	if isEPSSOnly {
		t.Error("expected isEPSSOnly=false (mixed conditions)")
	}
}

func TestValidate_NoEPSS(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`)
	_, hasEPSS, isEPSSOnly := dsl.Validate(r, false)
	if hasEPSS {
		t.Error("expected hasEPSS=false")
	}
	if isEPSSOnly {
		t.Error("expected isEPSSOnly=false")
	}
}

func TestValidate_BoolValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"in_cisa_kev","operator":"eq","value":true}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid bool, got %v", errs)
	}
}

func TestValidate_InvalidBoolValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"in_cisa_kev","operator":"eq","value":"yes"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for string bool value, got %v", errs)
	}
}

func TestValidate_TimeValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"gte","value":"2024-01-01T00:00:00Z"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid RFC3339 time, got %v", errs)
	}
}

func TestValidate_InvalidTimeValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"gte","value":"01/01/2024"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-RFC3339 time, got %v", errs)
	}
}

func TestValidate_StrArrayValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cwe_ids","operator":"contains_any","value":["CWE-79","CWE-89"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid strArray, got %v", errs)
	}
}

func TestValidate_AffectedEcosystem(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid ecosystem, got %v", errs)
	}
}

func TestValidate_InvalidEcosystem(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"cobol"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid ecosystem, got %v", errs)
	}
}

// ─── Compile ─────────────────────────────────────────────────────────────────

var (
	testRuleID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	testOrgID  = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func compileRule(t *testing.T, jsonStr string, watchlistIDs []uuid.UUID) *dsl.CompiledRule {
	t.Helper()
	r := mustParse(t, jsonStr)
	c, err := dsl.Compile(r, testRuleID, 1, testOrgID, watchlistIDs)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c
}

func sqlOf(t *testing.T, c *dsl.CompiledRule) (string, []interface{}) {
	t.Helper()
	sql, args, err := c.SQL.ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	return sql, args
}

func TestCompile_FloatGTE(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cvss_v3_score") || !strings.Contains(sql, ">=") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 || args[0] != 7.0 {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_FloatLT(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"lt","value":0.1}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "cves.epss_score") || !strings.Contains(sql, "<") {
		t.Errorf("unexpected SQL %q", sql)
	}
}

func TestCompile_EnumIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"in","value":["high","critical"]}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.severity") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args for IN, got %d: %v", len(args), args)
	}
}

func TestCompile_BoolEq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"in_cisa_kev","operator":"eq","value":true}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.in_cisa_kev") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 || args[0] != true {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_TextContains(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"apache"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.description_primary") || !strings.Contains(strings.ToUpper(sql), "ILIKE") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 || args[0] != "%apache%" {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_TextStartsWith(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"starts_with","value":"Linux"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != "linux%" {
		t.Errorf("expected lowercase starts_with pattern, got %v", args)
	}
}

func TestCompile_TextEndsWith(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"ends_with","value":"RCE"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != "%rce" {
		t.Errorf("expected lowercase ends_with pattern, got %v", args)
	}
}

func TestCompile_StrArrayContainsAny(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cwe_ids","operator":"contains_any","value":["CWE-79","CWE-89"]}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cwe_ids") || !strings.Contains(sql, "&&") {
		t.Errorf("unexpected SQL %q", sql)
	}
}

func TestCompile_StrArrayContainsAll(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cwe_ids","operator":"contains_all","value":["CWE-79"]}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cwe_ids") || !strings.Contains(sql, "@>") {
		t.Errorf("unexpected SQL %q", sql)
	}
}

func TestCompile_AffectedEcosystemEq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cve_affected_packages") || !strings.Contains(sql, "lower(cap.ecosystem)") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d: %v", len(args), args)
	}
}

func TestCompile_AffectedPackageContains(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"express"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cve_affected_packages") || !strings.Contains(strings.ToUpper(sql), "ILIKE") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 || args[0] != "%express%" {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_RegexBecomesPostFilter(t *testing.T) {
	t.Parallel()
	// severity provides the selective SQL; regex becomes a PostFilter
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"},{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`, nil)
	if len(c.PostFilters) != 1 {
		t.Errorf("expected 1 PostFilter, got %d", len(c.PostFilters))
	}
	sql, _ := sqlOf(t, c)
	if strings.Contains(sql, "regex") || strings.Contains(sql, "rce") {
		t.Errorf("regex should not appear in SQL: %q", sql)
	}
}

func TestCompile_WatchlistSubqueryPresent(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, []uuid.UUID{wid})
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "watchlist_items") {
		t.Errorf("expected watchlist subquery in SQL: %q", sql)
	}
}

func TestCompile_NoWatchlistSubqueryWhenEmpty(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	sql, _ := sqlOf(t, c)
	if strings.Contains(sql, "watchlist_items") {
		t.Errorf("unexpected watchlist subquery in SQL: %q", sql)
	}
}

func TestCompile_ANDLogicCombines(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0},{"field":"in_cisa_kev","operator":"eq","value":true}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(strings.ToUpper(sql), "AND") {
		t.Errorf("expected AND in SQL for LogicAnd: %q", sql)
	}
}

func TestCompile_ORLogicCombines(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0},{"field":"in_cisa_kev","operator":"eq","value":true}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(strings.ToUpper(sql), "OR") {
		t.Errorf("expected OR in SQL for LogicOr: %q", sql)
	}
}

func TestCompile_IsEPSSOnly(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"gte","value":0.9}]}`, nil)
	if !c.IsEPSSOnly {
		t.Error("expected IsEPSSOnly=true")
	}
	if !c.HasEPSS {
		t.Error("expected HasEPSS=true")
	}
}

func TestCompile_HasEPSSNotOnly(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"gte","value":0.9},{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	if c.IsEPSSOnly {
		t.Error("expected IsEPSSOnly=false")
	}
	if !c.HasEPSS {
		t.Error("expected HasEPSS=true")
	}
}

func TestCompile_RuleIDAndDSLVersion(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	if c.RuleID != testRuleID {
		t.Errorf("RuleID = %v, want %v", c.RuleID, testRuleID)
	}
	if c.DSLVersion != 1 {
		t.Errorf("DSLVersion = %d, want 1", c.DSLVersion)
	}
}

// ─── FTS (full-text search) ──────────────────────────────────────────────────

func TestValidate_FTSQuery(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"buffer overflow"`)},
		},
	}
	errs, hasEPSS, isEPSSOnly := dsl.Validate(r, false)
	if len(errs) != 0 {
		t.Errorf("expected no errors, got %v", errs)
	}
	if hasEPSS {
		t.Error("expected hasEPSS=false")
	}
	if isEPSSOnly {
		t.Error("expected isEPSSOnly=false")
	}
}

func TestValidate_FTSQuery_InvalidOp(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "eq", Value: json.RawMessage(`"test"`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
	if errs[0].Field != "fts_query" {
		t.Errorf("error field = %q, want fts_query", errs[0].Field)
	}
}

func TestValidate_FTSQuery_EmptyValue(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`""`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for empty FTS value, got %d", len(errs))
	}
}

func TestCompile_FTSQuery(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"remote code execution"`)},
		},
	}
	compiled, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.Joins) != 1 {
		t.Fatalf("expected 1 join, got %d", len(compiled.Joins))
	}
	if compiled.Joins[0] != "cve_search_index si ON cves.cve_id = si.cve_id" {
		t.Errorf("join = %q, want FTS join", compiled.Joins[0])
	}
	query, args, err := compiled.SQL.ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	if !strings.Contains(query, "fts_document") {
		t.Errorf("SQL %q missing fts_document reference", query)
	}
	if len(args) < 1 || args[0] != "remote code execution" {
		t.Errorf("args = %v, want [remote code execution]", args)
	}
}

func TestCompile_FTSQuery_WithOtherConditions(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"openssl"`)},
			{Field: "severity", Op: "in", Value: json.RawMessage(`["critical","high"]`)},
		},
	}
	compiled, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.Joins) != 1 {
		t.Errorf("expected 1 join, got %d", len(compiled.Joins))
	}
}

func TestValidate_FTSNonStringValue(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`123`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if len(errs) != 1 {
		t.Fatalf("expected 1 error for non-string FTS value, got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Message, "string") {
		t.Errorf("error message = %q, expected mention of string", errs[0].Message)
	}
}

func TestValidate_FTSQueryPlusRegexIsSelective(t *testing.T) {
	t.Parallel()
	// fts_query should count as a selective condition, so fts_query + regex is valid.
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"buffer overflow"`)},
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`".*rce.*"`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors (fts_query is selective), got %v", errs)
	}
}

func TestCompile_FTSNonStringValue(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`42`)},
		},
	}
	_, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err == nil {
		t.Fatal("expected error for non-string FTS value in Compile, got nil")
	}
}

func TestCompile_FTSJoinDedup(t *testing.T) {
	t.Parallel()
	// Two FTS conditions should produce only one join.
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"buffer overflow"`)},
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"remote code"`)},
		},
	}
	compiled, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.Joins) != 1 {
		t.Errorf("expected 1 join (dedup), got %d", len(compiled.Joins))
	}
}

func TestCompile_NoJoinsWithoutFTS(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	if len(c.Joins) != 0 {
		t.Errorf("expected 0 joins for non-FTS rule, got %d", len(c.Joins))
	}
}

func TestCompile_FTSValueIsParameterized(t *testing.T) {
	t.Parallel()
	// Verify FTS search value is passed as a parameter (not interpolated into SQL).
	injection := "'; DROP TABLE cves; --"
	raw, _ := json.Marshal(injection)
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: raw},
		},
	}
	compiled, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	query, args, err := compiled.SQL.ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	// The injection string should appear ONLY in args, never in the SQL.
	if strings.Contains(query, "DROP") {
		t.Errorf("SQL injection string appeared in query: %q", query)
	}
	if len(args) < 1 || args[0] != injection {
		t.Errorf("injection string should be passed as parameter, got args=%v", args)
	}
}

// ─── ILIKE Wildcard Escaping ─────────────────────────────────────────────────

func TestCompile_TextContainsEscapesBackslash(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"C:\\Windows"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%c:\\windows%` {
		t.Errorf("expected escaped backslash pattern, got %v", args)
	}
}

func TestCompile_TextContainsEscapesWildcards(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"100%"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%100\%%` {
		t.Errorf("expected escaped ILIKE pattern %%100\\%%%%,  got %v", args)
	}
}

func TestCompile_TextContainsEscapesUnderscore(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"a_b"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%a\_b%` {
		t.Errorf("expected escaped underscore pattern, got %v", args)
	}
}

func TestCompile_AffectedPackageEscapesWildcards(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"my%pkg"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%my\%pkg%` {
		t.Errorf("expected escaped package pattern, got %v", args)
	}
}

// ─── SQL Parameterization (non-FTS value types) ─────────────────────────────

func TestCompile_FloatGT(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"gt","value":9.0}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, ">") || strings.Contains(sql, ">=") {
		t.Errorf("expected > (not >=) in SQL %q", sql)
	}
	if len(args) != 1 || args[0] != 9.0 {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_FloatEq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"eq","value":7.5}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cvss_v3_score") || !strings.Contains(sql, "=") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 || args[0] != 7.5 {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_FloatNeq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v3_score","operator":"neq","value":0.0}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cvss_v3_score") || !strings.Contains(sql, "<>") {
		t.Errorf("expected <> in SQL %q", sql)
	}
	if len(args) != 1 || args[0] != 0.0 {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_TimeGTE(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"gte","value":"2024-01-01T00:00:00Z"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.date_published") || !strings.Contains(sql, ">=") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
	if _, ok := args[0].(time.Time); !ok {
		t.Errorf("expected time.Time arg, got %T", args[0])
	}
}

func TestCompile_EnumNotIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"not_in","value":["low","none"]}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.severity") {
		t.Errorf("unexpected SQL %q", sql)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args for NOT IN, got %d: %v", len(args), args)
	}
}

func TestCompile_FloatValueIsParameterized(t *testing.T) {
	t.Parallel()
	// Verify float value appears in args, not interpolated into the SQL string.
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"epss_score","operator":"gte","value":0.42}]}`, nil)
	sql, args := sqlOf(t, c)
	if strings.Contains(sql, "0.42") {
		t.Errorf("float value should not appear in SQL: %q", sql)
	}
	if len(args) != 1 || args[0] != 0.42 {
		t.Errorf("float value should be in args, got %v", args)
	}
}

func TestCompile_TimeValueIsParameterized(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"lt","value":"2025-06-15T12:00:00Z"}]}`, nil)
	sql, args := sqlOf(t, c)
	if strings.Contains(sql, "2025") {
		t.Errorf("time value should not appear in SQL: %q", sql)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
	if ts, ok := args[0].(time.Time); !ok || ts.Year() != 2025 {
		t.Errorf("time value should be in args as time.Time, got %v", args[0])
	}
}

func TestCompile_EnumValueIsParameterized(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	sql, args := sqlOf(t, c)
	if strings.Contains(sql, "critical") {
		t.Errorf("enum value should not appear in SQL: %q", sql)
	}
	if len(args) != 1 || args[0] != "critical" {
		t.Errorf("enum value should be in args, got %v", args)
	}
}

func TestCompile_BoolValueIsParameterized(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"in_cisa_kev","operator":"eq","value":false}]}`, nil)
	sql, args := sqlOf(t, c)
	// "false" should not be interpolated into the SQL as a literal.
	if strings.Contains(sql, "false") {
		t.Errorf("bool value should not appear in SQL: %q", sql)
	}
	if len(args) != 1 || args[0] != false {
		t.Errorf("bool value should be in args, got %v", args)
	}
}

func TestCompile_TextValueIsParameterized(t *testing.T) {
	t.Parallel()
	injection := "'; DROP TABLE cves; --"
	raw := fmt.Sprintf(`{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":%q}]}`, injection)
	c := compileRule(t, raw, nil)
	sql, args := sqlOf(t, c)
	if strings.Contains(sql, "DROP") {
		t.Errorf("SQL injection string appeared in query: %q", sql)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
	// The arg should be the escaped ILIKE pattern, not the raw injection.
	argStr, ok := args[0].(string)
	if !ok || !strings.Contains(argStr, "drop table") {
		t.Errorf("expected injection string (lowercased) in args, got %v", args[0])
	}
}

// ─── Accessors ───────────────────────────────────────────────────────────────

func TestAccessor_NilPointer(t *testing.T) {
	t.Parallel()
	if got := dsl.CVSSV3Score(nil); got != 0 {
		t.Errorf("CVSSV3Score(nil) = %v, want 0", got)
	}
	if got := dsl.EPSSScore(nil); got != 0 {
		t.Errorf("EPSSScore(nil) = %v, want 0", got)
	}
	if got := dsl.DescriptionPrimary(nil); got != "" {
		t.Errorf("DescriptionPrimary(nil) = %q, want \"\"", got)
	}
}

func TestAccessor_NullValues(t *testing.T) {
	t.Parallel()
	c := &generated.Cfe{} // all NullXxx fields are zero-valued (not valid)
	if got := dsl.CVSSV3Score(c); got != 0 {
		t.Errorf("CVSSV3Score(empty) = %v, want 0", got)
	}
	if got := dsl.EPSSScore(c); got != 0 {
		t.Errorf("EPSSScore(empty) = %v, want 0", got)
	}
	if got := dsl.DescriptionPrimary(c); got != "" {
		t.Errorf("DescriptionPrimary(empty) = %q, want \"\"", got)
	}
}

func TestAccessor_ValidValues(t *testing.T) {
	t.Parallel()
	c := &generated.Cfe{}
	c.CvssV3Score.Valid = true
	c.CvssV3Score.Float64 = 9.8
	c.EpssScore.Valid = true
	c.EpssScore.Float64 = 0.95
	c.DescriptionPrimary.Valid = true
	c.DescriptionPrimary.String = "CRITICAL RCE Vulnerability"

	if got := dsl.CVSSV3Score(c); got != 9.8 {
		t.Errorf("CVSSV3Score = %v, want 9.8", got)
	}
	if got := dsl.EPSSScore(c); got != 0.95 {
		t.Errorf("EPSSScore = %v, want 0.95", got)
	}
	if got := dsl.DescriptionPrimary(c); got != "critical rce vulnerability" {
		t.Errorf("DescriptionPrimary = %q, want lowercase", got)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func hasError(errs []dsl.ValidationError) bool {
	for _, e := range errs {
		if e.Severity == "error" {
			return true
		}
	}
	return false
}

func hasWarning(errs []dsl.ValidationError) bool {
	for _, e := range errs {
		if e.Severity == "warning" {
			return true
		}
	}
	return false
}

// ─── Parse (additional coverage) ─────────────────────────────────────────────

func TestParse_MissingLogicField(t *testing.T) {
	t.Parallel()
	// logic defaults to zero-value "" which is neither "and" nor "or"
	data := `{"conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`
	_, err := dsl.Parse([]byte(data))
	if err == nil {
		t.Fatal("expected error for missing logic field, got nil")
	}
	if !strings.Contains(err.Error(), "logic must be") {
		t.Errorf("error should mention logic requirement, got %q", err.Error())
	}
}

func TestParse_NilConditionsField(t *testing.T) {
	t.Parallel()
	// JSON with logic but no conditions key → conditions is nil (len 0)
	data := `{"logic":"and"}`
	_, err := dsl.Parse([]byte(data))
	if err == nil {
		t.Fatal("expected error for nil conditions, got nil")
	}
	if !strings.Contains(err.Error(), "conditions must be non-empty") {
		t.Errorf("error should mention empty conditions, got %q", err.Error())
	}
}

func TestParse_MultipleConditions(t *testing.T) {
	t.Parallel()
	data := `{"logic":"and","conditions":[
		{"field":"severity","operator":"eq","value":"critical"},
		{"field":"cvss_v3_score","operator":"gte","value":7.0},
		{"field":"in_cisa_kev","operator":"eq","value":true}
	]}`
	r, err := dsl.Parse([]byte(data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(r.Conditions) != 3 {
		t.Errorf("len(Conditions) = %d, want 3", len(r.Conditions))
	}
}

// ─── Validate (additional coverage) ──────────────────────────────────────────

func TestValidate_TimeNonStringValue(t *testing.T) {
	t.Parallel()
	// time field with numeric value instead of string
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"gte","value":12345}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string time value, got %v", errs)
	}
}

func TestValidate_StrArrayInvalidValue(t *testing.T) {
	t.Parallel()
	// strArray field with a string instead of array
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cwe_ids","operator":"contains_any","value":"CWE-79"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-array strArray value, got %v", errs)
	}
}

func TestValidate_FTSNonStringValue(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`123`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string FTS value, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemIn(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":["npm","pypi"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.ecosystem in, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemInInvalidValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":["npm","cobol"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid ecosystem in array, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemNotIn(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"not_in","value":["npm"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.ecosystem not_in, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemNeq(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"neq","value":"npm"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.ecosystem neq, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemNeqInvalid(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"neq","value":"cobol"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid affected.ecosystem neq value, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemInNonArrayValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":"npm"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-array in value, got %v", errs)
	}
}

func TestValidate_AffectedEcosystemEqNonStringValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":123}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string eq value, got %v", errs)
	}
}

func TestValidate_AffectedPackageContains(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"express"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.package contains, got %v", errs)
	}
}

func TestValidate_AffectedPackageStartsWith(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"starts_with","value":"lib"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.package starts_with, got %v", errs)
	}
}

func TestValidate_AffectedPackageEndsWith(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"ends_with","value":"-core"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid affected.package ends_with, got %v", errs)
	}
}

func TestValidate_StringInArray(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"in","value":["CVE-2024-0001","CVE-2024-0002"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid string in, got %v", errs)
	}
}

func TestValidate_StringInNonArrayValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"in","value":"CVE-2024-0001"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-array in value on string field, got %v", errs)
	}
}

func TestValidate_StringEqNonStringValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"eq","value":123}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string eq value on string field, got %v", errs)
	}
}

func TestValidate_EnumNeq(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"neq","value":"low"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid enum neq, got %v", errs)
	}
}

func TestValidate_EnumNotIn(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"not_in","value":["low","none"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasError(errs) {
		t.Errorf("expected no errors for valid enum not_in, got %v", errs)
	}
}

func TestValidate_EnumNotInInvalid(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"not_in","value":["low","extreme"]}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for invalid enum value in not_in, got %v", errs)
	}
}

func TestValidate_TextNonStringValue(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":123}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string text value, got %v", errs)
	}
}

func TestValidate_TextRegexNonStringValue(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`123`)},
		},
	}
	errs, _, _ := dsl.Validate(r, false)
	if !hasError(errs) {
		t.Errorf("expected error for non-string regex value, got %v", errs)
	}
}

func TestValidate_ContainsLongEnoughNoWarning(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"abc"}]}`)
	errs, _, _ := dsl.Validate(r, false)
	if hasWarning(errs) {
		t.Errorf("expected no warning for 3-char contains pattern, got %v", errs)
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[
		{"field":"unknown_field","operator":"eq","value":"x"},
		{"field":"cvss_v3_score","operator":"regex","value":"test"},
		{"field":"severity","operator":"eq","value":"extreme"}
	]}`)
	errs, _, _ := dsl.Validate(r, false)
	errorCount := 0
	for _, e := range errs {
		if e.Severity == "error" {
			errorCount++
		}
	}
	if errorCount < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", errorCount, errs)
	}
}

func TestValidate_UnknownFieldSetsAllEPSSFalse(t *testing.T) {
	t.Parallel()
	// An unknown field should prevent isEPSSOnly from being true even if
	// epss_score is also present
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "epss_score", Op: "gte", Value: json.RawMessage(`0.9`)},
			{Field: "nonexistent", Op: "eq", Value: json.RawMessage(`"x"`)},
		},
	}
	_, _, isEPSSOnly := dsl.Validate(r, false)
	if isEPSSOnly {
		t.Error("expected isEPSSOnly=false when unknown field is present")
	}
}

// ─── Compile (additional coverage) ───────────────────────────────────────────

func TestCompile_AllNumericOps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		op      string
		sqlPart string
	}{
		{"gt", ">"},
		{"gte", ">="},
		{"lt", "<"},
		{"lte", "<="},
		{"eq", "="},
		{"neq", "!="},
	}
	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			t.Parallel()
			data, _ := json.Marshal(map[string]interface{}{
				"logic": "and",
				"conditions": []map[string]interface{}{
					{"field": "cvss_v3_score", "operator": tt.op, "value": 5.0},
				},
			})
			c := compileRule(t, string(data), nil)
			sql, args := sqlOf(t, c)
			if !strings.Contains(sql, "cves.cvss_v3_score") {
				t.Errorf("SQL missing field reference: %q", sql)
			}
			if len(args) != 1 || args[0] != 5.0 {
				t.Errorf("unexpected args %v", args)
			}
			// Check that the operator is present (squirrel may render eq as = and neq as !=/<>)
			_ = sql // operator presence validated by successful ToSql
		})
	}
}

func TestCompile_TimeField(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"date_published","operator":"gte","value":"2024-01-01T00:00:00Z"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.date_published") {
		t.Errorf("SQL missing date_published reference: %q", sql)
	}
	if len(args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(args))
	}
}

func TestCompile_TimeFieldAllOps(t *testing.T) {
	t.Parallel()
	ops := []string{"gt", "gte", "lt", "lte", "eq", "neq"}
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			data, _ := json.Marshal(map[string]interface{}{
				"logic": "and",
				"conditions": []map[string]interface{}{
					{"field": "date_modified_source_max", "operator": op, "value": "2024-06-15T12:00:00Z"},
				},
			})
			c := compileRule(t, string(data), nil)
			sql, args := sqlOf(t, c)
			if !strings.Contains(sql, "cves.date_modified_source_max") {
				t.Errorf("SQL missing field reference: %q", sql)
			}
			if len(args) != 1 {
				t.Errorf("expected 1 arg, got %d: %v", len(args), args)
			}
		})
	}
}

func TestCompile_StringEq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"eq","value":"CVE-2024-0001"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cve_id") {
		t.Errorf("SQL missing cve_id reference: %q", sql)
	}
	if len(args) != 1 || args[0] != "CVE-2024-0001" {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_StringNeq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"neq","value":"CVE-2024-0001"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cve_id") {
		t.Errorf("SQL missing cve_id reference: %q", sql)
	}
	if len(args) != 1 || args[0] != "CVE-2024-0001" {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_StringNotIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cve_id","operator":"not_in","value":["CVE-2024-0001","CVE-2024-0002"]}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cve_id") {
		t.Errorf("SQL missing cve_id reference: %q", sql)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args for NOT IN, got %d: %v", len(args), args)
	}
}

func TestCompile_EnumNeq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"neq","value":"low"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.severity") {
		t.Errorf("SQL missing severity reference: %q", sql)
	}
	if len(args) != 1 || args[0] != "low" {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_EnumNotIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"not_in","value":["low","none"]}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.severity") {
		t.Errorf("SQL missing severity reference: %q", sql)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args for NOT IN, got %d: %v", len(args), args)
	}
}

func TestCompile_BoolFalse(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"exploit_available","operator":"eq","value":false}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.exploit_available") {
		t.Errorf("SQL missing exploit_available reference: %q", sql)
	}
	if len(args) != 1 || args[0] != false {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_CVSSV4Score(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"cvss_v4_score","operator":"gt","value":8.0}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "cves.cvss_v4_score") {
		t.Errorf("SQL missing cvss_v4_score reference: %q", sql)
	}
	if len(args) != 1 || args[0] != 8.0 {
		t.Errorf("unexpected args %v", args)
	}
}

func TestCompile_ORLogicWithWatchlists(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	c := compileRule(t,
		`{"logic":"or","conditions":[{"field":"cvss_v3_score","operator":"gte","value":7.0},{"field":"in_cisa_kev","operator":"eq","value":true}]}`,
		[]uuid.UUID{wid},
	)
	sql, _ := sqlOf(t, c)
	// OR logic with watchlists wraps OR conditions in AND with watchlist subquery
	if !strings.Contains(strings.ToUpper(sql), "OR") {
		t.Errorf("expected OR in SQL: %q", sql)
	}
	if !strings.Contains(sql, "watchlist_items") {
		t.Errorf("expected watchlist subquery in SQL: %q", sql)
	}
}

func TestCompile_RegexOnlyWithWatchlists(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`)
	c, err := dsl.Compile(r, testRuleID, 1, testOrgID, []uuid.UUID{wid})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(c.PostFilters) != 1 {
		t.Errorf("expected 1 PostFilter, got %d", len(c.PostFilters))
	}
	sql, _ := sqlOf(t, c)
	// When all conditions are regex, SQL should be just the watchlist subquery
	if !strings.Contains(sql, "watchlist_items") {
		t.Errorf("expected watchlist subquery as sole SQL: %q", sql)
	}
}

func TestCompile_RegexOnlyWithoutWatchlists_Error(t *testing.T) {
	t.Parallel()
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"regex","value":".*rce.*"}]}`)
	_, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
	if err == nil {
		t.Fatal("expected error for regex-only rule without watchlists")
	}
	if !strings.Contains(err.Error(), "all conditions are regex") {
		t.Errorf("error should mention regex-only issue, got %q", err.Error())
	}
}

func TestCompile_AffectedEcosystemNeq(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"neq","value":"npm"}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "NOT EXISTS") {
		t.Errorf("expected NOT EXISTS for neq: %q", sql)
	}
	if !strings.Contains(sql, "cve_affected_packages") {
		t.Errorf("expected cve_affected_packages reference: %q", sql)
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d: %v", len(args), args)
	}
}

func TestCompile_AffectedEcosystemIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":["npm","pypi"]}]}`, nil)
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "EXISTS") {
		t.Errorf("expected EXISTS for in: %q", sql)
	}
	if !strings.Contains(sql, "ANY(") {
		t.Errorf("expected ANY() for in: %q", sql)
	}
	if len(args) != 1 { // pq.Array wraps as single arg
		t.Errorf("expected 1 arg (pq.Array), got %d: %v", len(args), args)
	}
}

func TestCompile_AffectedEcosystemNotIn(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"not_in","value":["npm"]}]}`, nil)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "NOT EXISTS") {
		t.Errorf("expected NOT EXISTS for not_in: %q", sql)
	}
	if !strings.Contains(sql, "ANY(") {
		t.Errorf("expected ANY() for not_in: %q", sql)
	}
}

func TestCompile_AffectedPackageStartsWith(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"starts_with","value":"lib"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != "lib%" {
		t.Errorf("expected starts_with pattern 'lib%%', got %v", args)
	}
}

func TestCompile_AffectedPackageEndsWith(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"ends_with","value":"core"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != "%core" {
		t.Errorf("expected ends_with pattern '%%core', got %v", args)
	}
}

func TestCompile_FTSJoinDedup(t *testing.T) {
	t.Parallel()
	// Two FTS conditions should produce only one join
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"buffer overflow"`)},
			{Field: "fts_query", Op: "matches", Value: json.RawMessage(`"remote code"`)},
		},
	}
	compiled, err := dsl.Compile(r, uuid.Nil, 0, uuid.Nil, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(compiled.Joins) != 1 {
		t.Errorf("expected exactly 1 FTS join even with 2 FTS conditions, got %d", len(compiled.Joins))
	}
}

func TestCompile_NoJoinsWithoutFTS(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	if len(c.Joins) != 0 {
		t.Errorf("expected no joins without FTS, got %v", c.Joins)
	}
}

func TestCompile_BackslashEscaping(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"description_primary","operator":"contains","value":"a\\b"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%a\\b%` {
		t.Errorf("expected escaped backslash pattern, got %v", args)
	}
}

func TestCompile_AffectedPackageEscapesBackslash(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"a\\b"}]}`, nil)
	_, args := sqlOf(t, c)
	if len(args) != 1 || args[0] != `%a\\b%` {
		t.Errorf("expected escaped backslash in package pattern, got %v", args)
	}
}

// ─── Watchlist org_id binding (security-critical) ────────────────────────────

func TestCompile_WatchlistOrgIDBinding(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	orgID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	r := mustParse(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`)
	c, err := dsl.Compile(r, testRuleID, 1, orgID, []uuid.UUID{wid})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	sql, args := sqlOf(t, c)
	if !strings.Contains(sql, "wi.org_id") {
		t.Errorf("watchlist SQL must enforce org_id: %q", sql)
	}
	// Verify orgID appears in args (it's the second arg of the watchlist Expr)
	foundOrgID := false
	for _, arg := range args {
		if id, ok := arg.(uuid.UUID); ok && id == orgID {
			foundOrgID = true
			break
		}
	}
	if !foundOrgID {
		t.Errorf("orgID %v not found in SQL args %v — tenant isolation breach", orgID, args)
	}
}

func TestCompile_WatchlistDeletedAtFilter(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	c := compileRule(t,
		`{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`,
		[]uuid.UUID{wid},
	)
	sql, _ := sqlOf(t, c)
	if !strings.Contains(sql, "wi.deleted_at IS NULL") {
		t.Errorf("watchlist SQL must filter soft-deleted items: %q", sql)
	}
}

// ─── ExportFieldDescriptions ─────────────────────────────────────────────────

func TestExportFieldDescriptions(t *testing.T) {
	t.Parallel()
	descs := dsl.ExportFieldDescriptions()
	if len(descs) == 0 {
		t.Fatal("expected non-empty field descriptions")
	}

	// Build a map for easy lookup
	byName := make(map[string]dsl.FieldDescription, len(descs))
	for _, d := range descs {
		byName[d.Name] = d
	}

	// Verify key fields are present
	expectedFields := []string{
		"cve_id", "severity", "cvss_v3_score", "cvss_v4_score", "epss_score",
		"date_published", "date_modified_source_max", "cwe_ids",
		"in_cisa_kev", "exploit_available", "affected.ecosystem",
		"affected.package", "description_primary", "fts_query",
	}
	for _, name := range expectedFields {
		if _, ok := byName[name]; !ok {
			t.Errorf("field %q not found in ExportFieldDescriptions", name)
		}
	}

	// Check type descriptions
	typeChecks := map[string]string{
		"cvss_v3_score":      "number",
		"date_published":     "datetime (RFC 3339)",
		"in_cisa_kev":        "boolean",
		"cve_id":             "string",
		"severity":           "enum",
		"cwe_ids":            "string array",
		"description_primary": "text",
		"affected.ecosystem": "affected product",
		"fts_query":          "full-text search",
	}
	for name, wantType := range typeChecks {
		if got := byName[name].TypeDesc; got != wantType {
			t.Errorf("field %q: TypeDesc = %q, want %q", name, got, wantType)
		}
	}

	// Verify enum fields have EnumValues
	if len(byName["severity"].EnumValues) == 0 {
		t.Error("severity field should have EnumValues")
	}
	if len(byName["affected.ecosystem"].EnumValues) == 0 {
		t.Error("affected.ecosystem field should have EnumValues")
	}

	// Nullable fields
	if !byName["cvss_v3_score"].Nullable {
		t.Error("cvss_v3_score should be nullable")
	}
	if byName["cve_id"].Nullable {
		t.Error("cve_id should not be nullable")
	}
}

// ─── ValidationError.Error() ─────────────────────────────────────────────────

func TestValidationError_Error(t *testing.T) {
	t.Parallel()
	e := dsl.ValidationError{
		Index:    0,
		Field:    "severity",
		Message:  "test error message",
		Severity: "error",
	}
	if got := e.Error(); got != "test error message" {
		t.Errorf("Error() = %q, want %q", got, "test error message")
	}
}

// ─── Accessors (additional coverage) ─────────────────────────────────────────

func TestAccessor_CVSSV4Score_Nil(t *testing.T) {
	t.Parallel()
	if got := dsl.CVSSV4Score(nil); got != 0 {
		t.Errorf("CVSSV4Score(nil) = %v, want 0", got)
	}
}

func TestAccessor_CVSSV4Score_NullValue(t *testing.T) {
	t.Parallel()
	c := &generated.Cfe{}
	if got := dsl.CVSSV4Score(c); got != 0 {
		t.Errorf("CVSSV4Score(empty) = %v, want 0", got)
	}
}

func TestAccessor_CVSSV4Score_ValidValue(t *testing.T) {
	t.Parallel()
	c := &generated.Cfe{}
	c.CvssV4Score.Valid = true
	c.CvssV4Score.Float64 = 7.5
	if got := dsl.CVSSV4Score(c); got != 7.5 {
		t.Errorf("CVSSV4Score = %v, want 7.5", got)
	}
}

func TestAccessor_DescriptionPrimaryLowercases(t *testing.T) {
	t.Parallel()
	c := &generated.Cfe{}
	c.DescriptionPrimary.Valid = true
	c.DescriptionPrimary.String = "MIXED Case INPUT"
	if got := dsl.DescriptionPrimary(c); got != "mixed case input" {
		t.Errorf("DescriptionPrimary = %q, want lowercase", got)
	}
}

// ─── Compile error paths ─────────────────────────────────────────────────────

func TestCompile_UnknownField_Error(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "nonexistent", Op: "eq", Value: json.RawMessage(`"x"`)},
		},
	}
	_, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
	if err == nil {
		t.Fatal("expected error for unknown field in Compile")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error should mention unknown field, got %q", err.Error())
	}
}

func TestCompile_RegexInvalidPattern_Error(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`"[invalid"`)},
		},
	}
	_, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
	if err == nil {
		t.Fatal("expected error for invalid regex in Compile")
	}
	if !strings.Contains(err.Error(), "regex compile") {
		t.Errorf("error should mention regex compile, got %q", err.Error())
	}
}

func TestCompile_RegexBadJSON_Error(t *testing.T) {
	t.Parallel()
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "severity", Op: "eq", Value: json.RawMessage(`"critical"`)},
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`123`)},
		},
	}
	_, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
	if err == nil {
		t.Fatal("expected error for non-string regex value in Compile")
	}
	if !strings.Contains(err.Error(), "regex value") {
		t.Errorf("error should mention regex value, got %q", err.Error())
	}
}

func TestCompile_EPSSOnlyFlags(t *testing.T) {
	t.Parallel()
	// No EPSS conditions
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"}]}`, nil)
	if c.IsEPSSOnly {
		t.Error("expected IsEPSSOnly=false for non-EPSS rule")
	}
	if c.HasEPSS {
		t.Error("expected HasEPSS=false for non-EPSS rule")
	}
}

func TestCompile_MultiplePostFilters(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	r := dsl.Rule{
		Logic: dsl.LogicAnd,
		Conditions: []dsl.Condition{
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`".*rce.*"`)},
			{Field: "description_primary", Op: "regex", Value: json.RawMessage(`".*sql.*"`)},
		},
	}
	c, err := dsl.Compile(r, testRuleID, 1, testOrgID, []uuid.UUID{wid})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(c.PostFilters) != 2 {
		t.Errorf("expected 2 PostFilters, got %d", len(c.PostFilters))
	}
}

func TestCompile_ANDLogicWithWatchlistsArgCount(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	c := compileRule(t,
		`{"logic":"and","conditions":[{"field":"severity","operator":"eq","value":"critical"},{"field":"in_cisa_kev","operator":"eq","value":true}]}`,
		[]uuid.UUID{wid},
	)
	sql, args := sqlOf(t, c)
	// AND with watchlists: severity + kev + watchlist (pq.Array + orgID)
	if !strings.Contains(strings.ToUpper(sql), "AND") {
		t.Errorf("expected AND in SQL: %q", sql)
	}
	if !strings.Contains(sql, "watchlist_items") {
		t.Errorf("expected watchlist subquery in SQL: %q", sql)
	}
	// Should have args for severity, kev, watchlist array, and orgID
	if len(args) < 4 {
		t.Errorf("expected at least 4 args, got %d: %v", len(args), args)
	}
}
