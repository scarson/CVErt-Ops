// ABOUTME: Unit tests for the CVE-ID set predicates of affected.ecosystem, affected.package and affected.cpe_product.
// ABOUTME: Covers correlation, exact ecosystems, release arms, package folding, product terms, candidate IDs, limits, the "or" CVE set and bound arrays.
package dsl_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/check"
)

// foldedNameEq is the package predicate's folded-name comparison, the expression
// cve_affected_packages_check_idx indexes.
const foldedNameEq = `CASE WHEN cap.ecosystem = 'PyPI' THEN regexp_replace(lower(cap.package_name), '[-_.]+', '-', 'g') ELSE lower(cap.package_name) END = ANY(?)`

const (
	packageSetHead = "cves.cve_id IN (\n    SELECT cap.cve_id FROM cve_affected_packages cap"
	// packageBranchJoin is a package branch that follows another branch of one CVE set.
	packageBranchJoin = "\n    UNION ALL\n    SELECT cap.cve_id FROM cve_affected_packages cap"
	candidateLine     = "cap.cve_id = ANY(?)"
	ecosystemEq       = "cap.ecosystem = ANY(?)"
	releaseArm        = "cap.ecosystem LIKE ANY(?)"
	pypiArm           = "(cap.ecosystem = 'PyPI' AND "
	otherArm          = "(cap.ecosystem <> 'PyPI' AND "
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
	// One CVE set of an ecosystem branch and a package branch; only the ecosystem
	// branch has an ecosystem line.
	assertCount(t, sql, packageSetHead, 1)
	assertCount(t, sql, packageBranchJoin, 1)
	assertCount(t, sql, ecosystemEq, 1)
	assertCount(t, sql, pypiArm+foldedNameEq+")", 1)
	assertCount(t, sql, otherArm+foldedNameEq+")", 1)
	if strings.Contains(sql, ") OR cves.cve_id IN (") {
		t.Errorf("expected one set with the two branches joined by UNION ALL, got:\n%s", sql)
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

// ─── affected.cpe_product sets (design sections 3.2 and 5.1) ────────────────

const (
	productSetHead = "cves.cve_id IN (\n    SELECT m.cve_id FROM cve_cpe_matches m\n    WHERE m.vulnerable"
	cnaBranchHead  = "UNION ALL\n    SELECT a.cve_id FROM cve_cna_affected a"
	cpeRangeTerm   = "starts_with(m.cpe_normalized, ?)"
	nvdCandidate   = "m.cve_id = ANY(?)"
	cnaCandidate   = "a.cve_id = ANY(?)"
	// cnaNameTerm marks a name term: it compares the index expression on the
	// product, which an other-product exclusion never does.
	cnaNameTerm   = `left(lower(a.product), 256) COLLATE "C"`
	asciiBoundary = `!~ '^[a-z0-9]'`
)

// productRule is an "and" rule of affected.cpe_product conditions; each cond is
// raw JSON for the operator.
func productRule(conds ...string) string {
	return `{"logic":"and","conditions":[` + strings.Join(conds, ",") + `]}`
}

func productEq(v string) string {
	return `{"field":"affected.cpe_product","operator":"eq","value":"` + v + `"}`
}

// TestCompile_ProductSetNode checks nodejs:node.js's arguments (design section
// 3.2): two CPE spellings in three parts make 6 ranges of 3 arguments, and 5 CNA
// names make 5 exact-name terms of 4.
func TestCompile_ProductSetNode(t *testing.T) {
	t.Parallel()
	c := compileRule(t, productRule(productEq("nodejs:node.js")), nil)

	sql, args := whereOf(t, c, nil)
	if len(args) != 38 {
		t.Errorf("got %d args, want 38 (18 range + 20 name): %v", len(args), args)
	}
	assertCount(t, sql, productSetHead, 1)
	assertCount(t, sql, cnaBranchHead, 1)
	assertCount(t, sql, cpeRangeTerm, 6)
	assertCount(t, sql, "cve_id = ANY", 0)
	assertCount(t, sql, cnaNameTerm+" = ?", 5)
	assertCount(t, sql, "NOT (", 0)
	assertSetShapeRules(t, sql)
	var prefixes []string
	for _, spelling := range []string{"nodejs:node.js", "nodejs:nodejs"} {
		for _, part := range []string{"a", "o", "h"} {
			prefixes = append(prefixes, "cpe:2.3:"+part+":"+spelling+":")
		}
	}
	for _, p := range prefixes {
		lo := strings.TrimSuffix(p, ":")
		if !containsArgs(args, lo+":", lo+";", p) {
			t.Errorf("no range arguments %q, %q, %q in %v", lo+":", lo+";", p, args)
		}
	}
	for _, name := range [][2]string{
		{"nodejs", "node.js"}, {"nodejs", "nodejs"}, {"nodejs", "node"}, {"node.js", "node.js"}, {"the node.js project", "node.js"},
	} {
		if !containsArgs(args, name[0], name[1], name[0], name[1]) {
			t.Errorf("no exact-name arguments for %q / %q in %v", name[0], name[1], args)
		}
	}

	// With candidate IDs the prefixes and names are bound arrays.
	sql, args = whereOf(t, c, []string{"CVE-1"})
	if sql != "("+productCandidateSet+")" {
		t.Errorf("with one candidate, SQL:\n%s\nwant:\n%s", sql, "("+productCandidateSet+")")
	}
	if len(args) != 11 {
		t.Fatalf("with one candidate: got %d args, want 11", len(args))
	}
	assertArrayArgs(t, args[:4], []string{"CVE-1"}, prefixes,
		[]string{"nodejs", "nodejs", "nodejs", "node.js", "the node.js project"},
		[]string{"node.js", "nodejs", "node", "node.js", "node.js"})
	assertArrayArgs(t, args[6:7], []string{"CVE-1"})
}

// containsArgs reports whether args holds want as a contiguous run.
func containsArgs(args []interface{}, want ...string) bool {
	for i := 0; i+len(want) <= len(args); i++ {
		match := true
		for j, w := range want {
			if args[i+j] != w {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestCompile_ProductSetDotNetExcludesOtherProducts(t *testing.T) {
	t.Parallel()
	c := compileRule(t, productRule(productEq("microsoft:.net")), nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, "AND NOT (", 1)
	// Two prefix other products, each with the ASCII boundary test.
	assertCount(t, sql, asciiBoundary, 2)
	// The ".net " prefix name is a range on the product.
	assertCount(t, sql, cnaNameTerm+" >= ?", 1)
	assertSetShapeRules(t, sql)
	if !containsArgs(args, "microsoft", ".net framework", ".net framework") ||
		!containsArgs(args, "microsoft", "microsoft .net framework", "microsoft .net framework") ||
		!containsArgs(args, "microsoft", "openapi.net") {
		t.Errorf("other-product arguments missing from %v", args)
	}
}

// TestCompile_ProductSetExcludesOtherProductsPerValue checks each value's other
// products exclude rows only within that value's group (design section 5.1): the
// CNA row Microsoft / .NET Framework is an other product of microsoft:.net and a
// name of microsoft:.net_framework.
func TestCompile_ProductSetExcludesOtherProductsPerValue(t *testing.T) {
	t.Parallel()
	c := compileRule(t, productRule(`{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","microsoft:.net_framework"]}`), nil)
	sql, _ := whereOf(t, c, nil)
	assertCount(t, sql, productSetHead, 1)
	assertCount(t, sql, "AND NOT (", 1)
	notAt := strings.Index(sql, "AND NOT (")
	lastBoundary := strings.LastIndex(sql, asciiBoundary)
	if notAt < 0 || lastBoundary < notAt {
		t.Fatalf("expected one NOT group, got:\n%s", sql)
	}
	// The first value's four names (three exact, one prefix) precede its NOT
	// group; the second value's two exact names follow it.
	assertCount(t, sql[:notAt], cnaNameTerm+" = ?", 3)
	assertCount(t, sql[:notAt], cnaNameTerm+" >= ?", 1)
	assertCount(t, sql[lastBoundary:], cnaNameTerm+" = ?", 2)
	assertCount(t, sql[lastBoundary:], "NOT (", 0)
	// Three CPE spellings in three parts.
	assertCount(t, sql, cpeRangeTerm, 9)
}

func TestCompile_ProductSetRangesAreDistinctAcrossValues(t *testing.T) {
	t.Parallel()
	// Both spellings of one name table row read the same NVD rows.
	c := compileRule(t, productRule(`{"field":"affected.cpe_product","operator":"in","value":["nodejs:node.js","nodejs:nodejs"]}`), nil)
	sql, _ := whereOf(t, c, nil)
	assertCount(t, sql, cpeRangeTerm, 6)
	// Each value keeps its own name group.
	assertCount(t, sql, cnaNameTerm+" = ?", 10)
}

func TestCompile_ProductValuesAreOnlyArguments(t *testing.T) {
	t.Parallel()
	c := compileRule(t, productRule(productEq("NodeJS:Node.js")), nil)
	sql, args := whereOf(t, c, []string{"CVE-2026-56847"})
	for _, a := range args {
		s, ok := a.(string)
		if !ok {
			continue
		}
		if strings.Contains(sql, s) {
			t.Errorf("argument %q appears in the SQL text:\n%s", s, sql)
		}
	}
	for _, s := range []string{"nodejs", "NodeJS", "Node.js", "CVE-2026-56847"} {
		if strings.Contains(sql, s) {
			t.Errorf("value %q appears in the SQL text", s)
		}
	}
}

func TestCompile_ProductStoredRuleFailsClosed(t *testing.T) {
	t.Parallel()
	vals := make([]string, 51)
	for i := range vals {
		vals[i] = fmt.Sprintf("vendor%d:product%d", i, i)
	}
	list := func(vals []string) string {
		b, err := json.Marshal(vals)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return `{"field":"affected.cpe_product","operator":"in","value":` + string(b) + `}`
	}
	sameFifty := make([]string, 100)
	for i := range sameFifty {
		sameFifty[i] = list(vals[:50])
	}
	tests := []struct {
		name, rule, wantErr string
	}{
		{"malformed value", productRule(productEq("nodejs node.js")), "printable ASCII"},
		{"51 values", productRule(list(vals)), "a rule may name at most 50 products in total"},
		{"100 conditions of the same 50 values", productRule(sameFifty...), "a rule may name at most 50 products in total"},
		{"empty list", productRule(`{"field":"affected.cpe_product","operator":"in","value":[]}`), "value must list at least one item"},
		{"operator neq", productRule(`{"field":"affected.cpe_product","operator":"neq","value":"nodejs:node.js"}`), "operator"},
		{"operator regex", productRule(`{"field":"affected.cpe_product","operator":"regex","value":"node"}`, `{"field":"severity","operator":"eq","value":"high"}`), "operator"},
	}
	for _, tt := range tests {
		_, err := dsl.Compile(mustParse(t, tt.rule), testRuleID, 1, testOrgID, nil)
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: Compile error = %v, want one containing %q", tt.name, err, tt.wantErr)
		}
	}
	// 50 values compile.
	if _, err := dsl.Compile(mustParse(t, productRule(list(vals[:50]))), testRuleID, 1, testOrgID, nil); err != nil {
		t.Errorf("50 values: Compile: %v", err)
	}
}

// nameTableCPEs is every CPE spelling of the name table's rows
// (internal/check/names.go cnaTable), whose names table digest test pins it.
var nameTableCPEs = []string{
	"nodejs:node.js", "nodejs:nodejs", "php:php", "f5:nginx", "nginx:nginx", "f5:nginx_open_source",
	"microsoft:.net", "microsoft:.net_core", "postgresql:postgresql", "python:python",
}

// TestCompile_WorstRuleStaysUnderTheParameterLimit builds the worst rule the
// validator accepts (design section 5.2): 50 one-value product conditions, the
// name table's CPEs (which carry the most spellings, names and other products)
// and unmapped values with "_" in vendor and product (four own names each), plus
// 50 affected.package in conditions, with a 5,000-ID batch chunk. It binds 700
// arguments: 11 arrays per product set, which hold its candidates, prefixes,
// names and other products whatever their number, and 3 per package set.
func TestCompile_WorstRuleStaysUnderTheParameterLimit(t *testing.T) {
	t.Parallel()
	var conds []string
	for _, cpe := range nameTableCPEs {
		conds = append(conds, productEq(cpe))
	}
	for i := len(conds); i < 50; i++ {
		conds = append(conds, productEq(fmt.Sprintf("v_endor%d:p_roduct%d", i, i)))
	}
	for i := range 50 {
		conds = append(conds, fmt.Sprintf(`{"field":"affected.package","operator":"in","value":["pkg%d","other%d"]}`, i, i))
	}
	r := mustParse(t, productRule(conds...))
	errs, _, _ := dsl.Validate(r, false)
	for _, e := range errs {
		if e.Severity == "error" {
			t.Fatalf("Validate: unexpected error %+v", e)
		}
	}
	c, err := dsl.Compile(r, testRuleID, 1, testOrgID, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	ids := make([]string, 5000)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2026-%d", i)
	}
	_, args := whereOf(t, c, ids)
	if len(args) >= 10000 {
		t.Errorf("got %d args, want fewer than 10,000", len(args))
	}
	if len(args) != 700 {
		t.Errorf("got %d args, want 700 as counted in the comment", len(args))
	}
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

// ─── "or" rules: every set condition in one CVE set ─────────────────────────

const (
	cveSetHead = "cves.cve_id IN ("
	unionAll   = "\n    UNION ALL\n    "
)

// cveSetSpan returns the text of the rule's one CVE set, from its IN to the
// parenthesis that closes it, the first one at the start of a line.
func cveSetSpan(t *testing.T, sql string) string {
	t.Helper()
	start := strings.Index(sql, cveSetHead)
	if start < 0 {
		t.Fatalf("no CVE set in SQL:\n%s", sql)
	}
	end := strings.Index(sql[start:], "\n)")
	if end < 0 {
		t.Fatalf("CVE set is not closed in SQL:\n%s", sql)
	}
	return sql[start : start+end+2]
}

// TestCompile_OrSetConditionsAreOneCVESet checks two product conditions and a
// package condition under "or": one IN over five branches (CPE and CNA per
// product, one package branch), joined by UNION ALL.
func TestCompile_OrSetConditionsAreOneCVESet(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[`+productEq("nodejs:node.js")+`,`+productEq("php:php")+`,
		{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil)
	sql, args := whereOf(t, c, nil)
	assertCount(t, sql, cveSetHead, 1)
	assertCount(t, sql, unionAll, 4)
	assertCount(t, sql, "SELECT m.cve_id FROM cve_cpe_matches m", 2)
	assertCount(t, sql, "SELECT a.cve_id FROM cve_cna_affected a", 2)
	assertCount(t, sql, packageBranchJoin, 1)
	assertCount(t, sql, " OR cves.cve_id IN (", 0)
	assertSetShapeRules(t, sql)
	if span := cveSetSpan(t, sql); "("+span+")" != sql {
		t.Errorf("a rule of set conditions only should be its CVE set, got:\n%s", sql)
	}
	// The branches keep rule order, so the arguments are each condition's own,
	// in turn: the two product sets as each compiles alone, then the package's.
	var want []interface{}
	for _, v := range []string{"nodejs:node.js", "php:php"} {
		_, a := whereOf(t, compileRule(t, productRule(productEq(v)), nil), nil)
		want = append(want, a...)
	}
	_, pkgArgs := whereOf(t, compileRule(t, `{"logic":"and","conditions":[{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil), nil)
	want = append(want, pkgArgs...)
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %v, want %v", args, want)
	}
}

// TestCompile_OrSetsBesideScalars checks an "or" rule that mixes sets with scalar
// conditions: the one CVE set stands where the first set condition is, and the
// scalars, including the NOT EXISTS of a negative ecosystem, stay OR-ed beside it.
func TestCompile_OrSetsBesideScalars(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[
		{"field":"severity","operator":"eq","value":"critical"},
		`+productEq("nodejs:node.js")+`,
		{"field":"affected.ecosystem","operator":"neq","value":"npm"},
		{"field":"affected.package","operator":"in","value":["lodash","express"]},
		{"field":"in_cisa_kev","operator":"eq","value":true},
		{"field":"affected.ecosystem","operator":"eq","value":"PyPI"}]}`, nil)
	sql, _ := whereOf(t, c, nil)
	assertCount(t, sql, cveSetHead, 1)
	assertCount(t, sql, unionAll, 3)
	assertCount(t, sql, "NOT EXISTS (", 1)
	assertSetShapeRules(t, sql)
	if !strings.HasPrefix(sql, "(lower(cves.severity) = ? OR "+cveSetHead) {
		t.Errorf("expected severity, then the CVE set, got:\n%s", sql)
	}
	span := cveSetSpan(t, sql)
	for _, scalar := range []string{"lower(cves.severity) = ?", "NOT EXISTS (", "cves.in_cisa_kev = ?"} {
		assertCount(t, span, scalar, 0)
		assertCount(t, sql, scalar, 1)
	}
	if !strings.HasSuffix(sql, span+" OR NOT EXISTS (\n    SELECT 1 FROM cve_affected_packages cap\n    WHERE cap.cve_id = cves.cve_id\n      AND "+ecosystemEq+"\n) OR cves.in_cisa_kev = ?)") {
		t.Errorf("expected the CVE set, then the NOT EXISTS and KEV, got:\n%s", sql)
	}
}

// TestCompile_OrCVESetExactSQL pins a small mixed "or" rule's SQL and arguments
// with candidate IDs: each branch repeats the candidates before its own lines,
// and the arguments follow the placeholders in order.
func TestCompile_OrCVESetExactSQL(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[
		{"field":"severity","operator":"eq","value":"high"},
		{"field":"affected.package","operator":"eq","value":"lodash"},
		{"field":"affected.ecosystem","operator":"eq","value":"npm"},
		{"field":"in_cisa_kev","operator":"eq","value":true}]}`, nil)
	sql, args := whereOf(t, c, []string{"CVE-1"})
	want := `(lower(cves.severity) = ? OR cves.cve_id IN (
    SELECT cap.cve_id FROM cve_affected_packages cap
    WHERE cap.cve_id = ANY(?)
      AND ((cap.ecosystem = 'PyPI' AND ` + foldedNameEq + `) OR (cap.ecosystem <> 'PyPI' AND ` + foldedNameEq + `))
    UNION ALL
    SELECT cap.cve_id FROM cve_affected_packages cap
    WHERE cap.cve_id = ANY(?)
      AND cap.ecosystem = ANY(?)
) OR cves.in_cisa_kev = ?)`
	if sql != want {
		t.Errorf("SQL:\n%s\nwant:\n%s", sql, want)
	}
	if len(args) != 7 || args[0] != "high" || args[6] != true {
		t.Fatalf("args = %v, want high, five arrays, true", args)
	}
	assertArrayArgs(t, args[1:6], []string{"CVE-1"}, []string{"lodash"}, []string{"lodash"}, []string{"CVE-1"}, []string{"npm"})

	dollar, err := sq.Dollar.ReplacePlaceholders(sql)
	if err != nil {
		t.Fatalf("ReplacePlaceholders: %v", err)
	}
	// Placeholders run $1..$n, once each, in order, for n arguments.
	marks := regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(dollar, -1)
	if len(marks) != len(args) {
		t.Fatalf("%d placeholders for %d args:\n%s", len(marks), len(args), dollar)
	}
	for i, m := range marks {
		if m[1] != strconv.Itoa(i+1) {
			t.Errorf("placeholder %d is $%s, want $%d", i+1, m[1], i+1)
		}
	}
}

// TestCompile_OrCandidatesInEveryBranch checks the candidate line appears once in
// every branch of the one CVE set when there are candidates, and never without.
func TestCompile_OrCandidatesInEveryBranch(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[`+productEq("nodejs:node.js")+`,
		{"field":"affected.package","operator":"contains","value":"log"},
		{"field":"affected.ecosystem","operator":"in","value":["Debian"]},
		{"field":"cvss_v3_score","operator":"gte","value":9}]}`, nil)
	sql, _ := whereOf(t, c, nil)
	for _, line := range []string{nvdCandidate, cnaCandidate, candidateLine} {
		assertCount(t, sql, line, 0)
	}
	ids := []string{"CVE-1", "CVE-2"}
	sql, args := whereOf(t, c, ids)
	assertCount(t, sql, cveSetHead, 1)
	assertCount(t, sql, unionAll, 3)
	assertCount(t, sql, nvdCandidate, 1)
	assertCount(t, sql, cnaCandidate, 1)
	assertCount(t, sql, candidateLine, 2)
	n := 0
	for _, a := range args {
		if arr, ok := a.(*pq.StringArray); ok && reflect.DeepEqual(*arr, pq.StringArray(ids)) {
			n++
		}
	}
	if n != 4 {
		t.Errorf("candidate arrays = %d, want 4 (one per branch)", n)
	}
}

// TestCompile_OrWhereIsDeterministic checks Where returns the same SQL and
// arguments on every call, with and without candidates in between: the shared
// compiled rule is never changed by building its SQL.
func TestCompile_OrWhereIsDeterministic(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[`+productEq("microsoft:.net")+`,
		{"field":"affected.package","operator":"in","value":["a","b"]},
		{"field":"affected.ecosystem","operator":"eq","value":"npm"},
		{"field":"severity","operator":"eq","value":"low"}]}`, nil)
	sql1, args1 := whereOf(t, c, nil)
	whereOf(t, c, []string{"CVE-9"})
	sql2, args2 := whereOf(t, c, nil)
	if sql1 != sql2 || !reflect.DeepEqual(args1, args2) {
		t.Errorf("Where changed between calls:\n%s\n%v\nthen\n%s\n%v", sql1, args1, sql2, args2)
	}
	with1, wargs1 := whereOf(t, c, []string{"CVE-9"})
	with2, wargs2 := whereOf(t, c, []string{"CVE-9"})
	if with1 != with2 || !reflect.DeepEqual(wargs1, wargs2) {
		t.Errorf("Where with candidates changed between calls")
	}
}

// ─── Product sets with candidate IDs: bound arrays ──────────────────────────

const (
	// cpePrefixMatch is the candidate form's CPE test: one array of every prefix.
	cpePrefixMatch = "m.cpe_normalized ^@ ANY(?::text[])"
	// cnaNameJoin is the candidate form's CNA name join over bound arrays.
	cnaNameJoin = "JOIN unnest(?::text[], ?::text[], ?::boolean[], ?::int[]) AS n(v, p, is_prefix, grp)"
	// cpeIndexRange marks the no-candidate form's range on the CPE index expression.
	cpeIndexRange = `left(m.cpe_normalized, 512) COLLATE "C"`
)

// productCandidateSet is the whole candidate-form CVE set of one product set.
const productCandidateSet = `cves.cve_id IN (
    SELECT m.cve_id FROM cve_cpe_matches m
    WHERE m.vulnerable
      AND m.cve_id = ANY(?)
      AND m.cpe_normalized ^@ ANY(?::text[])
    UNION ALL
    SELECT a.cve_id FROM cve_cna_affected a
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
      )
)`

// assertPlaceholdersInOrder fails unless sql's placeholders, numbered by
// PostgreSQL's $n format, run $1..$n once each, in order, for n arguments.
func assertPlaceholdersInOrder(t *testing.T, sql string, nArgs int) {
	t.Helper()
	dollar, err := sq.Dollar.ReplacePlaceholders(sql)
	if err != nil {
		t.Fatalf("ReplacePlaceholders: %v", err)
	}
	marks := regexp.MustCompile(`\$(\d+)`).FindAllStringSubmatch(dollar, -1)
	if len(marks) != nArgs {
		t.Fatalf("%d placeholders for %d args:\n%s", len(marks), nArgs, dollar)
	}
	for i, m := range marks {
		if m[1] != strconv.Itoa(i+1) {
			t.Errorf("placeholder %d is $%s, want $%d", i+1, m[1], i+1)
		}
	}
}

// TestCompile_ProductCandidateFormExactSQL pins the candidate form of an "or"
// rule of two product conditions: one CPE branch and one CNA branch for all
// three values, with every prefix, name and other product a bound array, and
// groups numbered per value, so .NET's other products exclude rows only from
// .NET's names (design section 5.1).
func TestCompile_ProductCandidateFormExactSQL(t *testing.T) {
	t.Parallel()
	c := compileRule(t, `{"logic":"or","conditions":[`+productEq("nodejs:node.js")+`,
		{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","microsoft:.net_framework"]}]}`, nil)
	sql, args := whereOf(t, c, []string{"CVE-1"})
	if want := "(" + productCandidateSet + ")"; sql != want {
		t.Errorf("SQL:\n%s\nwant:\n%s", sql, want)
	}
	assertPlaceholdersInOrder(t, sql, len(args))

	var prefixes []string
	for _, cpe := range []string{"nodejs:node.js", "nodejs:nodejs", "microsoft:.net", "microsoft:.net_core", "microsoft:.net_framework"} {
		for _, part := range []string{"a", "o", "h"} {
			prefixes = append(prefixes, "cpe:2.3:"+part+":"+cpe+":")
		}
	}
	want := []interface{}{
		pq.Array([]string{"CVE-1"}),
		pq.Array(prefixes),
		pq.Array([]string{
			"nodejs", "nodejs", "nodejs", "node.js", "the node.js project",
			"microsoft", "microsoft", "microsoft", "microsoft",
			"microsoft", "microsoft",
		}),
		pq.Array([]string{
			"node.js", "nodejs", "node", "node.js", "node.js",
			".net", ".net core", ".net_core", ".net ",
			".net framework", ".net_framework",
		}),
		pq.Array([]bool{false, false, false, false, false, false, false, false, true, false, false}),
		pq.Array([]int64{0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2}),
		pq.Array([]string{"CVE-1"}),
		pq.Array([]int64{1, 1, 1}),
		pq.Array([]string{"microsoft", "microsoft", "microsoft"}),
		pq.Array([]string{".net framework", "microsoft .net framework", "openapi.net"}),
		pq.Array([]bool{true, true, false}),
	}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args:\n%#v\nwant:\n%#v", args, want)
	}
}

// TestCompile_ProductCandidateFormDoesNotGrowWithProducts checks the candidate
// form's SQL text and placeholders do not depend on the number of product
// values: an "or" rule of one product and one of 50 one-value conditions both
// bind 11 arguments, and neither holds a CPE or CNA index range.
func TestCompile_ProductCandidateFormDoesNotGrowWithProducts(t *testing.T) {
	t.Parallel()
	conds := make([]string, 0, 50)
	for _, cpe := range nameTableCPEs {
		conds = append(conds, productEq(cpe))
	}
	for i := len(conds); i < 50; i++ {
		conds = append(conds, productEq(fmt.Sprintf("v_endor%d:p_roduct%d", i, i)))
	}
	one := compileRule(t, `{"logic":"or","conditions":[`+conds[0]+`]}`, nil)
	fifty := compileRule(t, `{"logic":"or","conditions":[`+strings.Join(conds, ",")+`]}`, nil)
	ids := []string{"CVE-1", "CVE-2"}
	oneSQL, oneArgs := whereOf(t, one, ids)
	fiftySQL, fiftyArgs := whereOf(t, fifty, ids)
	if oneSQL != fiftySQL {
		t.Errorf("SQL differs between 1 and 50 products:\n%s\nand\n%s", oneSQL, fiftySQL)
	}
	if len(oneArgs) != 11 || len(fiftyArgs) != 11 {
		t.Errorf("args: %d for 1 product, %d for 50, want 11 each", len(oneArgs), len(fiftyArgs))
	}
	for _, sql := range []string{oneSQL, fiftySQL} {
		assertCount(t, sql, cpeRangeTerm, 0)
		assertCount(t, sql, "starts_with(m.cpe_normalized", 0)
		assertCount(t, sql, cpeIndexRange, 0)
		assertCount(t, sql, cnaNameTerm, 0)
		assertCount(t, sql, `left(lower(a.vendor), 256)`, 0)
		assertCount(t, sql, cpePrefixMatch, 1)
		assertCount(t, sql, cnaNameJoin, 1)
		assertCount(t, sql, nvdCandidate, 1)
		assertCount(t, sql, cnaCandidate, 1)
	}
	assertPlaceholdersInOrder(t, fiftySQL, len(fiftyArgs))

	// With no candidate IDs each condition keeps one range per part and CPE
	// spelling: 60 for the name table's CPEs, each of which reads its row's
	// spellings, and 3 for each of the 40 others.
	sql, _ := whereOf(t, fifty, nil)
	assertCount(t, sql, cpeRangeTerm, 60+3*40)
	assertCount(t, sql, cpePrefixMatch, 0)
	assertCount(t, sql, "unnest(", 0)
}

// TestCompile_ProductCandidateFormAndKeepsEachSet checks that under "and" each
// product condition keeps its own CPE and CNA branches with candidate IDs, so
// the rule matches the intersection of its sets.
func TestCompile_ProductCandidateFormAndKeepsEachSet(t *testing.T) {
	t.Parallel()
	c := compileRule(t, productRule(productEq("nodejs:node.js"), productEq("microsoft:.net"),
		`{"field":"severity","operator":"eq","value":"high"}`), nil)
	sql, args := whereOf(t, c, []string{"CVE-1"})
	want := "(" + productCandidateSet + " AND " + productCandidateSet + " AND lower(cves.severity) = ?)"
	if sql != want {
		t.Errorf("SQL:\n%s\nwant:\n%s", sql, want)
	}
	if len(args) != 23 {
		t.Fatalf("got %d args, want 23 (11 per product set, then severity)", len(args))
	}
	assertPlaceholdersInOrder(t, sql, len(args))
	// Each set holds only its own value's prefixes, numbered from group 0.
	assertArrayArgs(t, args[1:2], []string{
		"cpe:2.3:a:nodejs:node.js:", "cpe:2.3:o:nodejs:node.js:", "cpe:2.3:h:nodejs:node.js:",
		"cpe:2.3:a:nodejs:nodejs:", "cpe:2.3:o:nodejs:nodejs:", "cpe:2.3:h:nodejs:nodejs:",
	})
	assertArrayArgs(t, args[12:13], []string{
		"cpe:2.3:a:microsoft:.net:", "cpe:2.3:o:microsoft:.net:", "cpe:2.3:h:microsoft:.net:",
		"cpe:2.3:a:microsoft:.net_core:", "cpe:2.3:o:microsoft:.net_core:", "cpe:2.3:h:microsoft:.net_core:",
	})
	if got, want := args[16], pq.Array([]int64{0, 0, 0, 0}); !reflect.DeepEqual(got, want) {
		t.Errorf(".NET name groups = %#v, want %#v", got, want)
	}
	if got, want := args[18], pq.Array([]int64{0, 0, 0}); !reflect.DeepEqual(got, want) {
		t.Errorf(".NET other-product groups = %#v, want %#v", got, want)
	}
	// Node has no other products: its arrays are empty, never NULL.
	for i, w := range []interface{}{pq.Array([]int64{}), pq.Array([]string{}), pq.Array([]string{}), pq.Array([]bool{})} {
		if got := args[7+i]; !reflect.DeepEqual(got, w) {
			t.Errorf("Node other-product array %d = %#v, want %#v", i, got, w)
		}
	}
	if arr := args[7].(*pq.Int64Array); *arr == nil {
		t.Errorf("Node other-product groups bind NULL; want an empty array")
	}
}

// TestProductSetSQL_FormFollowsCandidates checks the exported set: the range
// form with no candidate IDs, the bound-array form with them.
func TestProductSetSQL_FormFollowsCandidates(t *testing.T) {
	t.Parallel()
	refs := []check.ProductRef{{Part: "a", Vendor: "nodejs", Product: "node.js"}}
	sql, _, err := dsl.ProductSetSQL(refs, nil).ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	assertCount(t, sql, cpeRangeTerm, 6)
	assertCount(t, sql, cpePrefixMatch, 0)
	sql, args, err := dsl.ProductSetSQL(refs, []string{"CVE-1"}).ToSql()
	if err != nil {
		t.Fatalf("ToSql: %v", err)
	}
	if sql != productCandidateSet {
		t.Errorf("SQL:\n%s\nwant:\n%s", sql, productCandidateSet)
	}
	if len(args) != 11 {
		t.Errorf("got %d args, want 11", len(args))
	}
}
