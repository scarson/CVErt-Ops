// ABOUTME: Tests for regex conditions: case-insensitive by default, patterns checked by Validate
// ABOUTME: as Compile checks them, and "or" rules refused when they combine regex with SQL conditions.
package dsl_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

// TestCompile_RegexIsCaseInsensitiveByDefault checks PLAN.md §10.2: a regex
// matches without regard to case unless the pattern sets its own flags.
func TestCompile_RegexIsCaseInsensitiveByDefault(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"description_primary", "cve_id"} {
		c := compileRule(t, ruleJSON("and", severityCritical,
			`{"field":"`+field+`","operator":"regex","value":"Apache HTTP"}`), nil)
		re := c.PostFilters[0].Pattern
		for _, s := range []string{"Apache HTTP Server", "apache http server", "APACHE HTTP"} {
			if !re.MatchString(s) {
				t.Errorf("%s: pattern %q does not match %q", field, re, s)
			}
		}
	}
}

// TestCompile_RegexFlagsInPatternOverrideDefault checks a pattern that turns
// case-insensitivity off itself matches case-sensitively.
func TestCompile_RegexFlagsInPatternOverrideDefault(t *testing.T) {
	t.Parallel()
	c := compileRule(t, ruleJSON("and", severityCritical,
		`{"field":"description_primary","operator":"regex","value":"(?-i)Apache"}`), nil)
	re := c.PostFilters[0].Pattern
	if !re.MatchString("Apache httpd") {
		t.Errorf("pattern %q does not match %q", re, "Apache httpd")
	}
	if re.MatchString("apache httpd") {
		t.Errorf("pattern %q matches %q, want case-sensitive", re, "apache httpd")
	}
}

// TestValidate_CVEIDRegexMustCompile checks Validate refuses an invalid cve_id
// pattern, which Compile refuses.
func TestValidate_CVEIDRegexMustCompile(t *testing.T) {
	t.Parallel()
	r := mustParse(t, ruleJSON("and", severityCritical,
		`{"field":"cve_id","operator":"regex","value":"[invalid"}`))
	errs, _, _ := dsl.Validate(r, false)
	if len(errs) != 1 || errs[0].Index != 1 || !strings.HasPrefix(errs[0].Message, "invalid regex") {
		t.Errorf("errors = %+v, want one invalid regex error on condition 1", errs)
	}
	if _, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil); err == nil {
		t.Error("Compile: want an error for an invalid cve_id regex")
	}
}

const msgOrRegexMixed = `an "or" rule cannot combine regex conditions with other conditions, because a regex is checked only on CVEs the other conditions match; put the regex conditions in a rule of their own`

// TestValidateCompile_OrRuleMixingRegexIsRefused checks an "or" rule cannot
// hold a regex beside other conditions: the regex is checked only on CVEs the
// SQL conditions select, so evaluating it would read the rule as "and".
func TestValidateCompile_OrRuleMixingRegexIsRefused(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	rules := map[string]string{
		"description regex beside severity": ruleJSON("or", severityCritical,
			`{"field":"description_primary","operator":"regex","value":"rce"}`),
		"cve_id regex beside product": ruleJSON("or", productCond("eq", `"nodejs:node.js"`),
			`{"field":"cve_id","operator":"regex","value":"CVE-2024-"}`),
	}
	for name, js := range rules {
		r := mustParse(t, js)
		for _, hasWatchlist := range []bool{false, true} {
			errs, _, _ := dsl.Validate(r, hasWatchlist)
			if got := findError(errs, msgOrRegexMixed); len(got) != 1 || got[0].Index != -1 {
				t.Errorf("%s (watchlist %v): entries = %+v, want the rule-level %q", name, hasWatchlist, errs, msgOrRegexMixed)
			}
		}
		_, err := dsl.Compile(r, testRuleID, 1, testOrgID, []uuid.UUID{wid})
		if err == nil || !strings.Contains(err.Error(), msgOrRegexMixed) {
			t.Errorf("%s: Compile error = %v, want %q", name, err, msgOrRegexMixed)
		}
	}
}

// TestValidateCompile_OrRuleOfOnlyRegexWithWatchlist checks an "or" rule whose
// conditions are all regex stays valid with a watchlist: the watchlist selects
// the candidates and any regex may match.
func TestValidateCompile_OrRuleOfOnlyRegexWithWatchlist(t *testing.T) {
	t.Parallel()
	wid := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	r := mustParse(t, ruleJSON("or",
		`{"field":"description_primary","operator":"regex","value":"apache"}`,
		`{"field":"description_primary","operator":"regex","value":"windows"}`))
	if errs, _, _ := dsl.Validate(r, true); len(errs) != 0 {
		t.Errorf("Validate: unexpected entries %+v", errs)
	}
	c, err := dsl.Compile(r, testRuleID, 1, testOrgID, []uuid.UUID{wid})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(c.PostFilters) != 2 {
		t.Errorf("PostFilters = %d, want 2", len(c.PostFilters))
	}
}

const msgRegexNeedsNarrowing = `a regex rule needs a condition that narrows the CVEs it is checked on (severity eq or in; in_cisa_kev eq true; date_published or date_modified_source_max gt, gte or eq; affected.ecosystem or affected.cpe_product eq or in; any affected.package condition; fts_query), or watchlist IDs`

// TestValidate_RegexNeedsANarrowingCondition checks PLAN.md §10.2's guardrail:
// a regex is a post-filter, so a rule without a watchlist needs a condition that
// narrows the SQL candidates. A condition on a selective field that keeps nearly
// every CVE does not count.
func TestValidate_RegexNeedsANarrowingCondition(t *testing.T) {
	t.Parallel()
	const regex = `{"field":"description_primary","operator":"regex","value":"apache"}`
	tests := []struct {
		cond   string
		narrow bool
	}{
		{`{"field":"severity","operator":"eq","value":"critical"}`, true},
		{`{"field":"severity","operator":"in","value":["critical","high"]}`, true},
		{`{"field":"severity","operator":"neq","value":"low"}`, false},
		{`{"field":"severity","operator":"not_in","value":["low"]}`, false},
		{`{"field":"in_cisa_kev","operator":"eq","value":true}`, true},
		{`{"field":"in_cisa_kev","operator":"eq","value":false}`, false},
		{`{"field":"date_published","operator":"gte","value":"2026-01-01T00:00:00Z"}`, true},
		{`{"field":"date_modified_source_max","operator":"gt","value":"2026-01-01T00:00:00Z"}`, true},
		{`{"field":"date_published","operator":"lt","value":"2026-01-01T00:00:00Z"}`, false},
		{`{"field":"date_published","operator":"neq","value":"2026-01-01T00:00:00Z"}`, false},
		{`{"field":"affected.ecosystem","operator":"eq","value":"npm"}`, true},
		{`{"field":"affected.ecosystem","operator":"neq","value":"npm"}`, false},
		{`{"field":"affected.ecosystem","operator":"not_in","value":["npm"]}`, false},
		{`{"field":"affected.package","operator":"contains","value":"lodash"}`, true},
		{`{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}`, true},
		{`{"field":"fts_query","operator":"matches","value":"apache"}`, true},
		{`{"field":"cvss_v3_score","operator":"gte","value":9}`, false},
	}
	for _, tt := range tests {
		r := mustParse(t, ruleJSON("and", tt.cond, regex))
		errs, _, _ := dsl.Validate(r, false)
		got := false
		for _, e := range errs {
			if e.Message == msgRegexNeedsNarrowing {
				got = true
				if e.Index != -1 || e.Severity != "error" {
					t.Errorf("%s: error %+v, want rule-level error", tt.cond, e)
				}
			}
		}
		if got == tt.narrow {
			t.Errorf("%s: narrowing error = %v, want %v (errors %+v)", tt.cond, got, !tt.narrow, errs)
		}
		// A watchlist narrows the candidates whatever the conditions.
		errs, _, _ = dsl.Validate(r, true)
		for _, e := range errs {
			if e.Message == msgRegexNeedsNarrowing {
				t.Errorf("%s with a watchlist: unexpected narrowing error", tt.cond)
			}
		}
	}
}
