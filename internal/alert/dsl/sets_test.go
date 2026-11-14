// ABOUTME: Unit tests for the CVE-ID set predicates of affected.ecosystem and affected.package conditions.
// ABOUTME: Covers correlation under "and", exact ecosystems, release arms, package folding and candidate IDs.
package dsl_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
)

// foldedNameEq is the package predicate's folded-name comparison, the expression
// cve_affected_packages_check_idx indexes.
const foldedNameEq = `CASE WHEN cap.ecosystem = 'PyPI' THEN regexp_replace(lower(cap.package_name), '[-_.]+', '-', 'g') ELSE lower(cap.package_name) END = ANY(?)`

const (
	packageSetHead = "cves.cve_id IN (\n    SELECT cap.cve_id FROM cve_affected_packages cap"
	candidateLine  = "cap.cve_id = ANY(?)"
	ecosystemEq    = "cap.ecosystem = ANY(?)"
	releaseArm     = "cap.ecosystem LIKE ANY(?)"
	pypiArm        = "(cap.ecosystem = 'PyPI' AND "
	otherArm       = "(cap.ecosystem <> 'PyPI' AND "
)

func whereOf(t *testing.T, c *dsl.CompiledRule, candidateIDs []string) (string, []interface{}) {
	t.Helper()
	sql, args, err := c.Where(candidateIDs).ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	return sql, args
}

// assertArrayArgs fails unless args are exactly the given arrays, in order.
func assertArrayArgs(t *testing.T, args []interface{}, want ...[]string) {
	t.Helper()
	if len(args) != len(want) {
		t.Fatalf("got %d args %v, want %d: %v", len(args), args, len(want), want)
	}
	for i, w := range want {
		got, ok := args[i].(*pq.StringArray)
		if !ok {
			t.Fatalf("arg %d is %T, want *pq.StringArray", i, args[i])
		}
		if !reflect.DeepEqual(*got, pq.StringArray(w)) {
			t.Errorf("arg %d = %q, want %q", i, *got, w)
		}
	}
}

// assertCount fails unless sub occurs exactly n times in sql.
func assertCount(t *testing.T, sql, sub string, n int) {
	t.Helper()
	if got := strings.Count(sql, sub); got != n {
		t.Errorf("%q occurs %d times, want %d, in SQL:\n%s", sub, got, n, sql)
	}
}

// assertSetShapeRules fails on any shape the set form must not use (pitfall DB-27,
// design section 13) and on lower-cased ecosystems (design section 4.1).
func assertSetShapeRules(t *testing.T, sql string) {
	t.Helper()
	for _, banned := range []string{"lower(cap.ecosystem)", "unnest(", "NOT IN", "WITH "} {
		if strings.Contains(sql, banned) {
			t.Errorf("SQL contains %q:\n%s", banned, sql)
		}
	}
}

func TestValidate_AffectedPackageAcceptsEqAndIn(t *testing.T) {
	t.Parallel()
	for _, cond := range []string{
		`{"field":"affected.package","operator":"eq","value":"lodash"}`,
		`{"field":"affected.package","operator":"in","value":["lodash","express"]}`,
	} {
		r := mustParse(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},`+cond+`]}`)
		errs, _, _ := dsl.Validate(r, false)
		if len(errs) != 0 {
			t.Errorf("%s: unexpected validation errors %v", cond, errs)
		}
	}
}

func TestCompile_PackageEqCorrelatesWithEcosystem(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil)

	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, releaseArm, 0)
	assertCount(t, sql, foldedNameEq, 1)
	assertCount(t, sql, pypiArm, 0)
	assertCount(t, sql, candidateLine, 0)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm"}, []string{"lodash"})

	sql, args = whereOf(t, c, []string{"CVE-1"})
	assertCount(t, sql, candidateLine, 1)
	assertArrayArgs(t, args, []string{"CVE-1"}, []string{"npm"}, []string{"lodash"})
}

func TestCompile_PackageEqWithReleaseEcosystem(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"Debian"},{"field":"affected.package","operator":"eq","value":"openssl"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	if !strings.Contains(sql, "("+ecosystemEq+" OR "+releaseArm+")") {
		t.Errorf("expected the ecosystem line with a release arm, got:\n%s", sql)
	}
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"Debian"}, []string{"Debian:%"}, []string{"openssl"})
}

func TestCompile_PackageEqMixedEcosystemsHasTwoArms(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":["npm","PyPI"]},{"field":"affected.package","operator":"eq","value":"Foo_Bar"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, pypiArm+foldedNameEq+")", 1)
	assertCount(t, sql, otherArm+foldedNameEq+")", 1)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm", "PyPI"}, []string{"foo-bar"}, []string{"foo_bar"})
}

func TestCompile_PackageInPyPIOnlyFoldsAndDeduplicates(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"PyPI"},{"field":"affected.package","operator":"in","value":["Foo_Bar","foo.bar","X"]}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, foldedNameEq, 1)
	assertCount(t, sql, pypiArm, 0)
	assertArrayArgs(t, args, []string{"PyPI"}, []string{"foo-bar", "x"})
}

func TestCompile_PackageInWithoutPyPILowerCasesAndDeduplicates(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"in","value":["Lodash","lodash","Foo_Bar"]}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, foldedNameEq, 1)
	assertCount(t, sql, pypiArm, 0)
	assertArrayArgs(t, args, []string{"npm"}, []string{"lodash", "foo_bar"})
}

func TestCompile_PackageEqUnderOrIsNotCorrelated(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	// One ecosystem set and one package set; only the ecosystem set has an ecosystem line.
	assertCount(t, sql, packageSetHead, 2)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, pypiArm+foldedNameEq+")", 1)
	assertCount(t, sql, otherArm+foldedNameEq+")", 1)
	if !strings.Contains(sql, ") OR cves.cve_id IN (") {
		t.Errorf("expected the two sets joined by OR, got:\n%s", sql)
	}
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm"}, []string{"lodash"}, []string{"lodash"})
}

func TestCompile_NegativeEcosystemStaysNotExists(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"neq","value":"npm"},{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil)
	sql, args := whereOf(t, c, []string{"CVE-1"})
	assertCount(t, sql, "NOT EXISTS (", 1)
	assertCount(t, sql, "cap.cve_id = cves.cve_id", 1)
	// The package set has no ecosystem line: the only ecosystem comparison is in NOT EXISTS.
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, pypiArm+foldedNameEq+")", 1)
	// The correlated NOT EXISTS does not carry the candidate IDs; the package set does.
	assertCount(t, sql, candidateLine, 1)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm"}, []string{"CVE-1"}, []string{"lodash"}, []string{"lodash"})
}

func TestCompile_NegativeEcosystemWithReleaseArm(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"not_in","value":["npm","Debian"]}]}`, nil)
	sql, args := whereOf(t, c, nil)
	if !strings.Contains(sql, "NOT EXISTS (") || !strings.Contains(sql, "("+ecosystemEq+" OR "+releaseArm+")") {
		t.Errorf("expected NOT EXISTS with a release arm, got:\n%s", sql)
	}
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm", "Debian"}, []string{"Debian:%"})
}

func TestCompile_EachPackageConditionIsItsOwnSet(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"a"},{"field":"affected.package","operator":"eq","value":"b"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	// Two package sets, each with the npm line, and no ecosystem set of its own.
	assertCount(t, sql, packageSetHead, 2)
	assertCount(t, sql, ecosystemEq, 2)
	assertCount(t, sql, foldedNameEq, 2)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm"}, []string{"a"}, []string{"npm"}, []string{"b"})

	sql, args = whereOf(t, c, []string{"CVE-1", "CVE-2"})
	assertCount(t, sql, candidateLine, 2)
	ids := []string{"CVE-1", "CVE-2"}
	assertArrayArgs(t, args, ids, []string{"npm"}, []string{"a"}, ids, []string{"npm"}, []string{"b"})
}

func TestCompile_EcosystemWithoutPackageIsItsOwnSet(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, "package_name", 0)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args, []string{"npm"})

	sql, args = whereOf(t, c, []string{"CVE-1"})
	assertCount(t, sql, candidateLine, 1)
	assertArrayArgs(t, args, []string{"CVE-1"}, []string{"npm"})
}

func TestCompile_TwoEcosystemConditionsWithoutPackageStaySeparate(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.ecosystem","operator":"eq","value":"PyPI"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 2)
	assertArrayArgs(t, args, []string{"npm"}, []string{"PyPI"})
}

func TestCompile_PackageContainsIsASet(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"LoDash"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, "lower(cap.package_name) ILIKE ?", 1)
	assertCount(t, sql, ecosystemEq, 0)
	assertSetShapeRules(t, sql)
	if len(args) != 1 || args[0] != "%lodash%" {
		t.Errorf("args = %v, want [%%lodash%%]", args)
	}
}

func TestCompile_PackageContainsCorrelatesWithEcosystem(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"contains","value":"lodash"},{"field":"affected.ecosystem","operator":"eq","value":"npm"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, "lower(cap.package_name) ILIKE ?", 1)
	if len(args) != 2 {
		t.Fatalf("args = %v, want the npm array then the pattern", args)
	}
	assertArrayArgs(t, args[:1], []string{"npm"})
	if args[1] != "%lodash%" {
		t.Errorf("pattern = %v, want %%lodash%%", args[1])
	}
}

func TestCompile_EcosystemValuesAreExactAndReleasesEscaped(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"in","value":["npm","Ubuntu:22.04","Red Hat:enterprise_linux:8"]}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertSetShapeRules(t, sql)
	assertArrayArgs(t, args,
		[]string{"npm", "Ubuntu:22.04", "Red Hat:enterprise_linux:8"},
		[]string{"Ubuntu:22.04:%", `Red Hat:enterprise\_linux:8:%`})
}

func TestCompile_EcosystemNullListBindsEmptyArray(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"in", "not_in"} {
		c := compileRule(t, `{"logic":"and","conditions":[{"field":"affected.ecosystem","operator":"`+op+`","value":null}]}`, nil)
		_, args := whereOf(t, c, nil)
		assertArrayArgs(t, args, []string{})
		if got := args[0].(*pq.StringArray); *got == nil {
			t.Errorf("%s: array arg is nil, which binds SQL NULL; want an empty array", op)
		}
	}
}
