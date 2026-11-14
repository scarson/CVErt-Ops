// ABOUTME: Tests for regex conditions: case-insensitive by default unless the pattern sets
// ABOUTME: its own flags, and patterns checked by Validate as Compile checks them.
package dsl_test

import (
	"strings"
	"testing"

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
