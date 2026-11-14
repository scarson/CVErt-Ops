// ABOUTME: Unit tests for the CVE-ID set predicates of affected.ecosystem, affected.package and affected.cpe_product.
// ABOUTME: Covers correlation, exact ecosystems, release arms, package folding, product terms, candidate IDs and limits.
package dsl_test

import (
	"encoding/json"
	"fmt"
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

	sql, args = whereOf(t, c, []string{"CVE-1"})
	if len(args) != 40 {
		t.Errorf("with one candidate: got %d args, want 40", len(args))
	}
	assertCount(t, sql, nvdCandidate, 1)
	assertCount(t, sql, cnaCandidate, 1)
	// Each branch's candidate array comes before its terms.
	assertArrayArgs(t, args[:1], []string{"CVE-1"})
	assertArrayArgs(t, args[19:20], []string{"CVE-1"})
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
// 50 affected.package in conditions, with a 5,000-ID batch chunk. It binds 1,590
// arguments: 360 for the mapped products, 25 for each of the 40 unmapped ones,
// 2 candidate arrays per product set and 3 arrays per package set.
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
	if len(args) != 1590 {
		t.Errorf("got %d args, want 1590 as counted in the comment", len(args))
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
