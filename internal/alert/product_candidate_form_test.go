// ABOUTME: Integration test that a product rule's two SQL forms agree: the range form with no candidate IDs
// ABOUTME: and the bound-array form with them, over the seeded corpus plus hand-built CNA and CPE rows.
package alert_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	cveFormDotNetFwAccent = "CVE-2026-31201" // CNA Microsoft / .NET Framework followed by a non-ASCII letter
	cveFormOpenSSL        = "CVE-2026-31202" // CNA OpenSSL / OpenSSL
	cveFormRubyOpenSSL    = "CVE-2026-31203" // CNA OpenSSL / OpenSSL extension of Ruby (git trunk), an other product
	cveFormAcmeCNA        = "CVE-2026-31204" // CNA Acme Corp / Web_Server, a name of acme_corp:web_server
	cveFormAcmeNVD        = "CVE-2026-31205" // NVD vulnerable acme_corp:web_server
	cveFormLongVendorA    = "CVE-2026-31206" // CNA vendor of 257 characters
	cveFormLongVendorB    = "CVE-2026-31207" // CNA vendor sharing the first 256 characters of the one above
)

// candidateFormCorpus is the hand-built rows the equivalence test adds to the
// product match corpus and the seeded corpus.
var candidateFormCorpus = []struct {
	cveID   string
	cna     []feed.CNAAffected
	matches []feed.CPEMatch
}{
	{cveID: cveFormDotNetFwAccent, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: ".NET Framework" + string(rune(0xE9))}}},
	{cveID: cveFormOpenSSL, cna: []feed.CNAAffected{{Vendor: "OpenSSL", Product: "OpenSSL"}}},
	{cveID: cveFormRubyOpenSSL, cna: []feed.CNAAffected{{Vendor: "OpenSSL", Product: "OpenSSL extension of Ruby (git trunk)"}}},
	{cveID: cveFormAcmeCNA, cna: []feed.CNAAffected{{Vendor: "Acme Corp", Product: "Web_Server"}}},
	{cveID: cveFormAcmeNVD, matches: []feed.CPEMatch{{CPE: cpe23("acme_corp:web_server"), CPENormalized: cpe23("acme_corp:web_server"), Vulnerable: true}}},
	{cveID: cveFormLongVendorA, cna: []feed.CNAAffected{{Vendor: strings.Repeat("x", 256) + "a", Product: "widget"}}},
	{cveID: cveFormLongVendorB, cna: []feed.CNAAffected{{Vendor: strings.Repeat("x", 256) + "b", Product: "widget"}}},
}

// ruleMatches runs compiled as the evaluator's candidate query does
// (candidateQuery): its WHERE for candidateIDs, the rejected/withdrawn filter,
// and the outer filter on candidateIDs when there are any. It returns the
// matched CVE IDs, sorted.
func ruleMatches(t *testing.T, ctx context.Context, tdb *testutil.TestDB, compiled *dsl.CompiledRule, candidateIDs []string) []string {
	t.Helper()
	combined := sq.And{
		compiled.Where(candidateIDs),
		sq.Expr("COALESCE(lower(cves.status), '') NOT IN ('rejected', 'withdrawn')"),
	}
	if len(candidateIDs) > 0 {
		combined = append(combined, sq.Expr("cves.cve_id = ANY(?)", pq.Array(candidateIDs)))
	}
	query, args, err := sq.Select("cves.cve_id").From("cves").Where(combined).
		OrderBy("cves.cve_id").PlaceholderFormat(sq.Dollar).ToSql()
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	return queryCVEIDs(t, ctx, tdb.DB(), query, args...)
}

// TestProductMatch_CandidateFormEqualsRangeForm checks that every product rule
// matches the same CVEs with no candidate IDs (the range form) as with all CVE
// IDs at once and in pages of two (the bound-array form), under "and" and "or",
// alone and mixed with other product and scalar conditions. Each rule must also
// match the CVEs it names and none it excludes, so equality cannot pass on two
// empty answers.
func TestProductMatch_CandidateFormEqualsRangeForm(t *testing.T) {
	// Not parallel: the NVD golden fixtures set an environment variable.
	tdb := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	ingestProductMatchCorpus(t, ctx, tdb)
	for _, row := range candidateFormCorpus {
		ingestCNAAndMatches(t, ctx, tdb, row.cveID, row.cna, row.matches)
	}

	const (
		cveFastify = "CVE-2026-107832" // seeded: CNA fastify / fastify only, severity LOW
		cveNode    = "CVE-2026-56847"  // seeded: CNA nodejs / node and NVD nodejs:node.js
		cveBrotli  = "CVE-2026-111497" // seeded: CNA Google / Brotli; NVD lists Node
	)
	product := func(v string) string {
		return `{"field":"affected.cpe_product","operator":"eq","value":"` + v + `"}`
	}
	const dotNetOrFramework = `{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","microsoft:.net_framework"]}`
	rules := []struct {
		name, logic string
		conditions  []string
		include     []string // CVEs the rule must match
		exclude     []string // CVEs the rule must not match
	}{
		{"node", "and", []string{product("nodejs:node.js")},
			[]string{cveProdNodeCNA, cveProdNodeProject, cveProdNodeNVD, cveProdNodejsNVD, cveNode, cveBrotli},
			[]string{cveProdNodePlatform, cveProdNodeRejected}},
		{".net", "and", []string{product("microsoft:.net")},
			[]string{cveProdDotNet9, cveProdDotNetFwExt},
			[]string{cveProdDotNetFw48, cveProdOpenAPINet, cveProdDotNetFw, cveFormDotNetFwAccent}},
		{".net or .net_framework in one list", "and", []string{dotNetOrFramework},
			[]string{cveProdDotNet9, cveProdDotNetFwExt, cveProdDotNetFw},
			[]string{cveProdDotNetFw48, cveProdOpenAPINet, cveFormDotNetFwAccent}},
		{"openssl", "and", []string{product("openssl:openssl")},
			[]string{cveFormOpenSSL}, []string{cveFormRubyOpenSSL}},
		{"brotli", "and", []string{product("google:brotli")}, []string{cveBrotli}, []string{cveNode}},
		{"fastify", "and", []string{product("fastify:fastify")}, []string{cveFastify}, nil},
		{"unmapped value with underscores", "and", []string{product("acme_corp:web_server")},
			[]string{cveFormAcmeCNA, cveFormAcmeNVD}, nil},
		{"or: node, .net list", "or", []string{product("nodejs:node.js"), dotNetOrFramework},
			[]string{cveProdNodeCNA, cveProdNodeNVD, cveProdDotNet9, cveProdDotNetFw},
			[]string{cveProdDotNetFw48, cveFormDotNetFwAccent, cveProdNodePlatform}},
		{"or: brotli, fastify, severity", "or",
			[]string{product("google:brotli"), product("fastify:fastify"), `{"field":"severity","operator":"eq","value":"critical"}`},
			[]string{cveBrotli, cveFastify}, nil},
		{"or: openssl, unmapped, KEV", "or",
			[]string{product("openssl:openssl"), product("acme_corp:web_server"), `{"field":"in_cisa_kev","operator":"eq","value":true}`},
			[]string{cveFormOpenSSL, cveFormAcmeCNA, cveFormAcmeNVD}, []string{cveFormRubyOpenSSL}},
		{"and: .net, .net list", "and", []string{product("microsoft:.net"), dotNetOrFramework},
			[]string{cveProdDotNet9, cveProdDotNetFwExt}, []string{cveProdDotNetFw}},
		{"and: node, brotli", "and", []string{product("nodejs:node.js"), product("google:brotli")},
			[]string{cveBrotli}, []string{cveNode}},
		{"and: fastify, severity", "and", []string{product("fastify:fastify"), `{"field":"severity","operator":"eq","value":"low"}`},
			[]string{cveFastify}, nil},
	}

	allIDs := queryCVEIDs(t, ctx, tdb.DB(), `SELECT cve_id FROM cves ORDER BY cve_id`)
	if len(allIDs) < 65 {
		t.Fatalf("corpus holds %d CVEs, want the seeded corpus and the hand-built rows", len(allIDs))
	}
	for _, r := range rules {
		t.Run(r.name, func(t *testing.T) {
			rule, err := dsl.Parse([]byte(`{"logic":"` + r.logic + `","conditions":[` + strings.Join(r.conditions, ",") + `]}`))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			compiled, err := dsl.Compile(rule, uuid.New(), 1, orgID, nil)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rangeForm := ruleMatches(t, ctx, tdb, compiled, nil)
			for _, id := range r.include {
				if !slices.Contains(rangeForm, id) {
					t.Errorf("range form: %s not matched; matched %v", id, rangeForm)
				}
			}
			for _, id := range r.exclude {
				if slices.Contains(rangeForm, id) {
					t.Errorf("range form: %s matched; it must not be", id)
				}
			}

			if all := ruleMatches(t, ctx, tdb, compiled, allIDs); !slices.Equal(all, rangeForm) {
				t.Errorf("candidate form over all %d IDs matched %v, range form %v", len(allIDs), all, rangeForm)
			}
			var paged []string
			for page := range slices.Chunk(allIDs, 2) {
				paged = append(paged, ruleMatches(t, ctx, tdb, compiled, page)...)
			}
			if !slices.Equal(paged, rangeForm) {
				t.Errorf("candidate form in pages of 2 matched %v, range form %v", paged, rangeForm)
			}
		})
	}
}
