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
