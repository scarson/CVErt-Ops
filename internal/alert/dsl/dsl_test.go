// ABOUTME: Unit tests for the alert DSL compiler: Parse, Validate, Compile, and accessors.
// ABOUTME: Pure logic tests — no database required.
package dsl_test

import (
	"encoding/json"
	"strings"
	"testing"

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

// ─── ILIKE Wildcard Escaping ─────────────────────────────────────────────────

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
