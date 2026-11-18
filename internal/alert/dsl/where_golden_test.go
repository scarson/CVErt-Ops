// ABOUTME: Pins the exact WHERE SQL and arguments of "and" rules and of "or" rules with one set condition.
// ABOUTME: The golden file holds the text; run with -update-where-golden to rewrite it after a deliberate change.
package dsl_test

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

var updateWhereGolden = flag.Bool("update-where-golden", false, "rewrite testdata/where.golden")

// whereGoldenRules are rules whose compiled SQL must not change: every "and"
// shape (one set predicate per condition, package conditions correlated with
// eq/in ecosystem conditions) and "or" rules with a single set condition.
var whereGoldenRules = []struct {
	name       string
	rule       string
	watchlists []uuid.UUID
}{
	{"and: correlated ecosystem and package, severity", `{"logic":"and","conditions":[
		{"field":"affected.ecosystem","operator":"eq","value":"npm"},
		{"field":"affected.package","operator":"eq","value":"lodash"},
		{"field":"severity","operator":"eq","value":"high"}]}`, nil},
	{"and: product, package list, KEV, CVSS", `{"logic":"and","conditions":[
		{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"},
		{"field":"affected.package","operator":"in","value":["Foo_Bar","express"]},
		{"field":"in_cisa_kev","operator":"eq","value":true},
		{"field":"cvss_v3_score","operator":"gte","value":7}]}`, nil},
	{"and: negative ecosystem, package contains, release ecosystem", `{"logic":"and","conditions":[
		{"field":"affected.ecosystem","operator":"neq","value":"npm"},
		{"field":"affected.package","operator":"contains","value":"ssl"},
		{"field":"affected.ecosystem","operator":"in","value":["Debian","PyPI"]}]}`, nil},
	{"and: two products, ecosystem without package", `{"logic":"and","conditions":[
		{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","php:php"]},
		{"field":"affected.cpe_product","operator":"eq","value":"acme:widget"},
		{"field":"affected.ecosystem","operator":"eq","value":"PyPI"}]}`, nil},
	{"and: package, FTS, watchlist", `{"logic":"and","conditions":[
		{"field":"affected.package","operator":"starts_with","value":"log"},
		{"field":"fts_query","operator":"matches","value":"remote code"}]}`,
		[]uuid.UUID{uuid.MustParse("33333333-3333-3333-3333-333333333333")}},
	{"or: one product, severity, KEV", `{"logic":"or","conditions":[
		{"field":"severity","operator":"eq","value":"critical"},
		{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"},
		{"field":"in_cisa_kev","operator":"eq","value":true}]}`, nil},
	{"or: one package, negative ecosystem, CWE, watchlist", `{"logic":"or","conditions":[
		{"field":"affected.ecosystem","operator":"not_in","value":["npm"]},
		{"field":"affected.package","operator":"in","value":["lodash"]},
		{"field":"cwe_ids","operator":"contains_any","value":["CWE-79"]}]}`,
		[]uuid.UUID{uuid.MustParse("33333333-3333-3333-3333-333333333333")}},
	{"or: two products, package, severity", `{"logic":"or","conditions":[
		{"field":"affected.cpe_product","operator":"eq","value":"openssl:openssl"},
		{"field":"severity","operator":"eq","value":"critical"},
		{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","acme_corp:web_server"]},
		{"field":"affected.package","operator":"eq","value":"lodash"}]}`, nil},
}

// renderWhere writes a rule's WHERE SQL and arguments, one argument per line.
func renderWhere(t *testing.T, b *strings.Builder, name, rule string, watchlists []uuid.UUID, candidateIDs []string) {
	t.Helper()
	c := compileRule(t, rule, watchlists)
	sql, args := whereOf(t, c, candidateIDs)
	fmt.Fprintf(b, "=== %s, candidates %q\n%s\n", name, candidateIDs, sql)
	for i, a := range args {
		if arr, ok := a.(*pq.StringArray); ok {
			fmt.Fprintf(b, "arg %d: %q\n", i, []string(*arr))
			continue
		}
		fmt.Fprintf(b, "arg %d: %T %#v\n", i, a, a)
	}
}

// TestWhere_UnchangedShapesMatchGolden pins the SQL of rules whose sets each
// keep their own IN predicate.
func TestWhere_UnchangedShapesMatchGolden(t *testing.T) {
	t.Parallel()
	var b strings.Builder
	for _, r := range whereGoldenRules {
		renderWhere(t, &b, r.name, r.rule, r.watchlists, nil)
		renderWhere(t, &b, r.name, r.rule, r.watchlists, []string{"CVE-1", "CVE-2"})
	}
	path := filepath.Join("testdata", "where.golden")
	if *updateWhereGolden {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: fixed test fixture path
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	// A checkout with core.autocrlf converts the golden file's line endings.
	if got := b.String(); got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("WHERE SQL differs from %s; got:\n%s", path, got)
	}
}
