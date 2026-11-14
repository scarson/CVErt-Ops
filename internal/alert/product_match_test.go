// ABOUTME: Integration tests for affected.cpe_product rules: NVD and CNA sources, other products, the
// ABOUTME: full-name recheck, SQL and Go agreeing on other products, one answer on every path, and acceptance.
package alert_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/alert/dsl"
	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	cveProdNodeCNA      = "CVE-2026-31001" // CNA Node.js / Node.js
	cveProdNodeProject  = "CVE-2026-31002" // CNA The Node.js Project / Node.js
	cveProdNodeNVD      = "CVE-2026-31003" // NVD vulnerable nodejs:node.js
	cveProdNodejsNVD    = "CVE-2026-31004" // NVD vulnerable nodejs:nodejs, the row's other spelling
	cveProdNodePlatform = "CVE-2026-31005" // NVD nodejs:node.js only as a platform (vulnerable false)
	cveProdNodeRejected = "CVE-2026-31006" // CNA Node.js / Node.js, rejected
	cveProdDotNet9      = "CVE-2026-31007" // CNA Microsoft / .NET 9.0 runtime
	cveProdDotNetFw48   = "CVE-2026-31008" // CNA Microsoft / .NET Framework 4.8
	cveProdOpenAPINet   = "CVE-2026-31009" // CNA Microsoft / OpenAPI.NET
	cveProdDotNetFwExt  = "CVE-2026-31010" // CNA Microsoft / .NET FrameworkExtensions
	cveProdDotNetFw     = "CVE-2026-31011" // CNA Microsoft / .NET Framework
)

// cpe23 is a CPE 2.3 name for vendor:product in part a with every other attribute "*".
func cpe23(vendorProduct string) string {
	return "cpe:2.3:a:" + vendorProduct + ":*:*:*:*:*:*:*:*"
}

var productMatchCorpus = []struct {
	cveID   string
	cna     []feed.CNAAffected
	matches []feed.CPEMatch
}{
	{cveID: cveProdNodeCNA, cna: []feed.CNAAffected{{Vendor: "Node.js", Product: "Node.js"}}},
	{cveID: cveProdNodeProject, cna: []feed.CNAAffected{{Vendor: "The Node.js Project", Product: "Node.js"}}},
	{cveID: cveProdNodeNVD, matches: []feed.CPEMatch{{CPE: cpe23("nodejs:node.js"), CPENormalized: cpe23("nodejs:node.js"), Vulnerable: true}}},
	{cveID: cveProdNodejsNVD, matches: []feed.CPEMatch{{CPE: cpe23("nodejs:nodejs"), CPENormalized: cpe23("nodejs:nodejs"), Vulnerable: true}}},
	{cveID: cveProdNodePlatform, matches: []feed.CPEMatch{
		{CPE: cpe23("example:widget"), CPENormalized: cpe23("example:widget"), Vulnerable: true},
		{CPE: cpe23("nodejs:node.js"), CPENormalized: cpe23("nodejs:node.js"), Vulnerable: false},
	}},
	{cveID: cveProdNodeRejected, cna: []feed.CNAAffected{{Vendor: "Node.js", Product: "Node.js"}}},
	{cveID: cveProdDotNet9, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: ".NET 9.0 runtime"}}},
	{cveID: cveProdDotNetFw48, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: ".NET Framework 4.8"}}},
	{cveID: cveProdOpenAPINet, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: "OpenAPI.NET"}}},
	{cveID: cveProdDotNetFwExt, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: ".NET FrameworkExtensions"}}},
	{cveID: cveProdDotNetFw, cna: []feed.CNAAffected{{Vendor: "Microsoft", Product: ".NET Framework"}}},
}

// ingestCNAAndMatches merges a CVE's CNA entries as a MITRE record and its CPE
// matches, with their criteria as affected CPEs, as an NVD record.
func ingestCNAAndMatches(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID string, cna []feed.CNAAffected, matches []feed.CPEMatch) {
	t.Helper()
	if len(cna) > 0 {
		patch := feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, CNAAffected: cna}
		if err := merge.Ingest(ctx, tdb.Store, patch, "mitre"); err != nil {
			t.Fatalf("merge.Ingest(%s, mitre): %v", cveID, err)
		}
	}
	if len(matches) > 0 {
		patch := feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, CPEMatches: matches}
		for _, m := range matches {
			patch.AffectedCPEs = append(patch.AffectedCPEs, feed.AffectedCPE{CPE: m.CPE, CPENormalized: m.CPENormalized})
		}
		if err := merge.Ingest(ctx, tdb.Store, patch, "nvd"); err != nil {
			t.Fatalf("merge.Ingest(%s, nvd): %v", cveID, err)
		}
	}
}

// ingestProductMatchCorpus merges every corpus CVE and rejects cveProdNodeRejected
// through an NVD record.
func ingestProductMatchCorpus(t *testing.T, ctx context.Context, tdb *testutil.TestDB) {
	t.Helper()
	for _, row := range productMatchCorpus {
		ingestCNAAndMatches(t, ctx, tdb, row.cveID, row.cna, row.matches)
	}
	rejected := feed.CanonicalPatch{CVEID: cveProdNodeRejected, SourceID: cveProdNodeRejected, Status: "Rejected"}
	if err := merge.Ingest(ctx, tdb.Store, rejected, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(%s, nvd): %v", cveProdNodeRejected, err)
	}

	// The rejected CVE keeps the CNA row the Node rule matches, so its exclusion is
	// the status filter's doing.
	var status string
	var rows int
	if err := tdb.DB().QueryRowContext(ctx, `
		SELECT c.status, (SELECT count(*) FROM cve_cna_affected a
		                  WHERE a.cve_id = c.cve_id AND a.vendor = 'Node.js' AND a.product = 'Node.js')
		FROM cves c WHERE c.cve_id = $1`, cveProdNodeRejected).Scan(&status, &rows); err != nil {
		t.Fatalf("read %s: %v", cveProdNodeRejected, err)
	}
	if status != "Rejected" || rows != 1 {
		t.Fatalf("%s: status %q with %d Node.js CNA rows, want Rejected with 1", cveProdNodeRejected, status, rows)
	}
	// The platform CVE's only Node row is not vulnerable.
	var vulnerable sql.NullBool
	if err := tdb.DB().QueryRowContext(ctx, `
		SELECT bool_or(vulnerable) FROM cve_cpe_matches
		WHERE cve_id = $1 AND cpe_normalized LIKE 'cpe:2.3:a:nodejs:%'`, cveProdNodePlatform).Scan(&vulnerable); err != nil {
		t.Fatalf("read %s: %v", cveProdNodePlatform, err)
	}
	if !vulnerable.Valid || vulnerable.Bool {
		t.Fatalf("%s: Node rows vulnerable = %v, want one row, not vulnerable", cveProdNodePlatform, vulnerable)
	}
}

// assertRuleEventsOnly checks every CVE in corpus: one event for each CVE in want, none for the rest.
func assertRuleEventsOnly(t *testing.T, db *sql.DB, ruleID uuid.UUID, corpus, want []string) {
	t.Helper()
	for _, cveID := range corpus {
		wantEvents := 0
		if slices.Contains(want, cveID) {
			wantEvents = 1
		}
		if n := countAlertEvents(t, db, ruleID, cveID); n != wantEvents {
			t.Errorf("%d events on %s, want %d", n, cveID, wantEvents)
		}
	}
}

// assertRuleMatchesOnEveryCandidatePath runs one rule through realtime, one CVE at
// a time, and a second through an activation scan, and checks both write events
// for exactly the CVEs in want among corpus.
func assertRuleMatchesOnEveryCandidatePath(t *testing.T, ctx context.Context, tdb *testutil.TestDB, ev *alert.Evaluator,
	orgID uuid.UUID, logic, conditions string, corpus, want []string) {
	t.Helper()
	rule := mustRule(t, ctx, tdb.Store, orgID, logic, conditions, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)
	if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
		t.Fatalf("realtime rule status %q, want active", s)
	}
	for _, cveID := range corpus {
		if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
			t.Fatalf("EvaluateRealtime(%s): %v", cveID, err)
		}
	}
	if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
		t.Fatalf("realtime rule status after evaluation %q, want active", s)
	}
	assertRuleEventsOnly(t, tdb.DB(), rule.ID, corpus, want)

	scan := createActivatingRule(t, ctx, tdb, orgID, logic, conditions)
	if err := ev.EvaluateActivation(ctx, scan.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}
	if s := getRuleStatus(t, tdb.DB(), scan.ID); s != "active" {
		t.Fatalf("activation rule status %q, want active", s)
	}
	assertRuleEventsOnly(t, tdb.DB(), scan.ID, corpus, want)
}

func TestProductMatch_RuleConditions(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	ingestProductMatchCorpus(t, ctx, tdb)

	corpus := make([]string, 0, len(productMatchCorpus))
	for _, row := range productMatchCorpus {
		corpus = append(corpus, row.cveID)
	}
	tests := []struct {
		name       string
		conditions string
		want       []string
	}{
		{
			// Two CNA spellings from the name table, NVD under both CPE spellings; a
			// platform CPE and a rejected CVE do not match.
			"nodejs:node.js",
			`[{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}]`,
			[]string{cveProdNodeCNA, cveProdNodeProject, cveProdNodeNVD, cveProdNodejsNVD},
		},
		{
			// The ".net " prefix name, without the .NET Framework and OpenAPI.NET
			// products; a prefix other product ends at an ASCII word boundary.
			"microsoft:.net",
			`[{"field":"affected.cpe_product","operator":"eq","value":"microsoft:.net"}]`,
			[]string{cveProdDotNet9, cveProdDotNetFwExt},
		},
		{
			// .NET Framework is an other product of the first value and a name of the second.
			"in microsoft:.net and microsoft:.net_framework",
			`[{"field":"affected.cpe_product","operator":"in","value":["microsoft:.net","microsoft:.net_framework"]}]`,
			[]string{cveProdDotNet9, cveProdDotNetFwExt, cveProdDotNetFw},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertRuleMatchesOnEveryCandidatePath(t, ctx, tdb, ev, orgID, "and", tt.conditions, corpus, tt.want)
		})
	}
}

// TestProductMatch_FullNameRecheck checks the exact-name term rechecks the whole
// vendor, which the index cuts to 256 characters, in the range form (no
// candidate IDs) and the bound-array form (candidate IDs). Rule values are at
// most 255 characters, so the set is built directly with a longer vendor.
func TestProductMatch_FullNameRecheck(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	const (
		cveLongA = "CVE-2026-31101"
		cveLongB = "CVE-2026-31102"
	)
	vendorA := strings.Repeat("x", 256) + "a"
	vendorB := strings.Repeat("x", 256) + "b" // same first 256 characters as vendorA
	ingestCNAAndMatches(t, ctx, tdb, cveLongA, []feed.CNAAffected{{Vendor: vendorA, Product: "widget"}}, nil)
	ingestCNAAndMatches(t, ctx, tdb, cveLongB, []feed.CNAAffected{{Vendor: vendorB, Product: "widget"}}, nil)

	both := []string{cveLongA, cveLongB}
	for _, candidateIDs := range [][]string{nil, both} {
		set := dsl.ProductSetSQL([]check.ProductRef{{Vendor: vendorA, Product: "widget"}}, candidateIDs)
		query, args, err := sq.Select("cves.cve_id").From("cves").Where(set).
			Where(sq.Expr("cves.cve_id = ANY(?)", pq.Array(both))).
			OrderBy("cves.cve_id").PlaceholderFormat(sq.Dollar).ToSql()
		if err != nil {
			t.Fatalf("build query: %v", err)
		}
		got := queryCVEIDs(t, ctx, tdb.DB(), query, args...)
		if !slices.Equal(got, []string{cveLongA}) {
			t.Errorf("candidates %v: matched %v, want only %s (vendor %d characters)", candidateIDs, got, cveLongA, len(vendorA))
		}
	}
}

// queryCVEIDs runs query and returns the first column of every row.
func queryCVEIDs(t *testing.T, ctx context.Context, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		t.Fatalf("query: %v\n%s", err, query)
	}
	defer rows.Close() //nolint:errcheck // read-only query
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return ids
}

// TestProductMatch_ParityWithIsOtherProduct checks the SQL exclusion and
// check.IsOtherProduct agree for every other product of the table's CPEs, with
// the other product's name followed by an ASCII letter, a digit, a space,
// nothing and a non-ASCII letter (design section 12).
func TestProductMatch_ParityWithIsOtherProduct(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()

	eAcute := string(rune(0xE9))
	for _, cpe := range []string{"microsoft:.net", "microsoft:.net_core", "openssl:openssl"} {
		p, err := check.ParseProductValue(cpe)
		if err != nil {
			t.Fatalf("ParseProductValue(%s): %v", cpe, err)
		}
		others := check.OtherProductsFor(p)
		if len(others) == 0 {
			t.Fatalf("%s has no other products", cpe)
		}
		for _, o := range others {
			for _, suffix := range []string{"a", "7", " ", "", eAcute} {
				vendor, product := o.Vendor, o.Product+suffix
				want := check.IsOtherProduct(others, vendor, product)
				// The Go rule itself: a prefix is followed by a boundary, an exact name by nothing.
				if boundary := suffix == "" || suffix == " " || suffix == eAcute; want != (boundary && (o.Prefix || suffix == "")) {
					t.Errorf("%s: IsOtherProduct(%q, %q) = %v, against the ASCII boundary rule", cpe, vendor, product, want)
				}

				// Built entirely by squirrel, so every placeholder is numbered once.
				query, args, err := sq.Select().
					Column(dsl.OtherProductSQL("lower(t.v)", "lower(t.p)", others)).
					FromSelect(sq.Select().Column(sq.Expr("?::text AS v", vendor)).Column(sq.Expr("?::text AS p", product)), "t").
					PlaceholderFormat(sq.Dollar).ToSql()
				if err != nil {
					t.Fatalf("build query: %v", err)
				}
				var got bool
				if err := tdb.DB().QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
					t.Fatalf("query %q: %v\n%s", product, err, query)
				}
				if got != want {
					t.Errorf("%s: SQL says %v, IsOtherProduct says %v, for %q / %q", cpe, got, want, vendor, product)
				}
			}
		}
	}
}

// activationMatches runs an activation scan of a new rule and returns the CVE IDs
// of the events it writes, sorted.
func activationMatches(t *testing.T, ctx context.Context, tdb *testutil.TestDB, ev *alert.Evaluator, orgID uuid.UUID, logic, conditions string) []string {
	t.Helper()
	rule := createActivatingRule(t, ctx, tdb, orgID, logic, conditions)
	if err := ev.EvaluateActivation(ctx, rule.ID, orgID); err != nil {
		t.Fatalf("EvaluateActivation: %v", err)
	}
	if s := getRuleStatus(t, tdb.DB(), rule.ID); s != "active" {
		t.Fatalf("activation rule status %q, want active", s)
	}
	return queryCVEIDs(t, ctx, tdb.DB(), `SELECT cve_id FROM alert_events WHERE rule_id = $1 ORDER BY cve_id`, rule.ID)
}

func TestProductMatch_SeededCorpus(t *testing.T) {
	// Not parallel: the NVD golden fixtures set an environment variable.
	tdb := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, tdb)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())

	const (
		cveFastify = "CVE-2026-107832" // awaiting analysis: CNA fastify / fastify only
		cveNode    = "CVE-2026-56847"  // CNA nodejs / node and NVD nodejs:node.js
		cveBrotli  = "CVE-2026-111497" // CNA Google / Brotli; NVD lists Node
	)
	// The fixture's only severity for the fastify CVE is CVSS 3.1 3.7 LOW, and it
	// has no NVD CPE row; the rule must match it through the CNA name alone.
	var severity string
	var nvdRows int
	if err := tdb.DB().QueryRowContext(ctx, `
		SELECT c.severity, (SELECT count(*) FROM cve_cpe_matches m WHERE m.cve_id = c.cve_id)
		FROM cves c WHERE c.cve_id = $1`, cveFastify).Scan(&severity, &nvdRows); err != nil {
		t.Fatalf("read %s: %v", cveFastify, err)
	}
	if severity != "LOW" || nvdRows != 0 {
		t.Fatalf("%s: severity %q with %d CPE match rows, want LOW with 0; the golden fixture changed", cveFastify, severity, nvdRows)
	}

	fastify := func(severities string) string {
		return `[{"field":"affected.cpe_product","operator":"eq","value":"fastify:fastify"},` +
			`{"field":"severity","operator":"in","value":` + severities + `}]`
	}
	if got := activationMatches(t, ctx, tdb, ev, orgID, "and", fastify(`["critical","high","medium","low"]`)); !slices.Contains(got, cveFastify) {
		t.Errorf("fastify:fastify with low: matched %v, want %s among them", got, cveFastify)
	}
	if got := activationMatches(t, ctx, tdb, ev, orgID, "and", fastify(`["critical","high","medium"]`)); slices.Contains(got, cveFastify) {
		t.Errorf("fastify:fastify without low: matched %v, want no %s", got, cveFastify)
	}

	node := activationMatches(t, ctx, tdb, ev, orgID, "and", `[{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}]`)
	if want := []string{cveBrotli, cveNode}; !slices.Equal(node, want) { // sorted by CVE ID text
		t.Errorf("nodejs:node.js: matched %v, want %v", node, want)
	}
	brotli := activationMatches(t, ctx, tdb, ev, orgID, "and", `[{"field":"affected.cpe_product","operator":"eq","value":"google:brotli"}]`)
	if want := []string{cveBrotli}; !slices.Equal(brotli, want) {
		t.Errorf("google:brotli: matched %v, want %v", brotli, want)
	}
}

// TestProductMatch_SameAnswerOnEveryPath checks the two forms of one rule agree
// (design sections 5.2 and 12): store.ExecuteDSLQuery, paged to the end with no
// candidate IDs, returns the CVEs an activation scan writes events for, in
// candidate pages, and DryRun counts the same number. An "or" rule's search also
// returns exactly the CVEs its conditions return alone.
func TestProductMatch_SameAnswerOnEveryPath(t *testing.T) {
	// Not parallel: the NVD golden fixtures set an environment variable.
	tdb := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, tdb)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	// PyPI and npm rows named foo-bar, and npm and PyPI lodash rows, for the
	// package names rule.
	ingestPackageMatchCorpus(t, ctx, tdb)

	// Package names under "or" share one branch: Foo_Bar folds to foo-bar for the
	// PyPI row only, and lodash and jspdf are npm names.
	const packageNames = `[{"field":"affected.package","operator":"eq","value":"Foo_Bar"},{"field":"affected.package","operator":"eq","value":"lodash"},{"field":"affected.package","operator":"in","value":["jspdf"]}]`
	rules := []struct {
		name, logic, conditions string
		// empty marks a rule the seeded corpus gives no match: fastify is there
		// only as a CNA product, with no package row. The npm jspdf rule checks
		// the correlated package set on a CVE that has one.
		empty bool
	}{
		{"product", "and", `[{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}]`, false},
		{"product or KEV", "or", `[{"field":"affected.cpe_product","operator":"eq","value":"google:brotli"},{"field":"in_cisa_kev","operator":"eq","value":true}]`, false},
		{"correlated package", "and", `[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"fastify"}]`, true},
		{"correlated package with a match", "and", `[{"field":"affected.ecosystem","operator":"eq","value":"npm"},{"field":"affected.package","operator":"eq","value":"jspdf"}]`, false},
		{"package or product", "or", `[{"field":"affected.package","operator":"eq","value":"lodash"},{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"}]`, false},
		{"product, package, ecosystem or KEV", "or", `[{"field":"affected.cpe_product","operator":"eq","value":"google:brotli"},{"field":"affected.package","operator":"eq","value":"jspdf"},{"field":"affected.ecosystem","operator":"eq","value":"Maven"},{"field":"in_cisa_kev","operator":"eq","value":true}]`, false},
		{"negative ecosystem", "and", `[{"field":"affected.ecosystem","operator":"neq","value":"npm"},{"field":"severity","operator":"eq","value":"high"}]`, false},
		{"package names", "or", packageNames, false},
	}
	// search pages store.ExecuteDSLQuery to the end and returns the sorted CVE IDs.
	search := func(t *testing.T, logic, conditions string) []string {
		t.Helper()
		rule, err := dsl.Parse([]byte(`{"logic":"` + logic + `","conditions":` + conditions + `}`))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		compiled, err := dsl.Compile(rule, uuid.New(), 1, orgID, nil)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		var searched []string
		cursor := ""
		for {
			rows, next, err := tdb.ExecuteDSLQuery(ctx, compiled, cursor, 100)
			if err != nil {
				t.Fatalf("ExecuteDSLQuery: %v", err)
			}
			for _, row := range rows {
				searched = append(searched, row.CveID)
			}
			if next == "" {
				break
			}
			cursor = next
		}
		slices.Sort(searched)
		return searched
	}
	for _, r := range rules {
		t.Run(r.name, func(t *testing.T) {
			searched := search(t, r.logic, r.conditions)
			if r.logic == "or" {
				// An "or" rule matches each CVE that one of its conditions matches alone,
				// so the one CVE set its set conditions compile to loses and adds nothing.
				var conds []json.RawMessage
				if err := json.Unmarshal([]byte(r.conditions), &conds); err != nil {
					t.Fatalf("conditions: %v", err)
				}
				var union []string
				for _, c := range conds {
					alone := search(t, "and", "["+string(c)+"]")
					t.Logf("%s alone: %d CVEs", c, len(alone))
					union = append(union, alone...)
				}
				slices.Sort(union)
				union = slices.Compact(union)
				if !slices.Equal(searched, union) {
					t.Errorf("or rule returned %v, its conditions alone %v", searched, union)
				}
			}

			activated := activationMatches(t, ctx, tdb, ev, orgID, r.logic, r.conditions)
			if !slices.Equal(searched, activated) {
				t.Errorf("search returned %v, activation wrote events for %v", searched, activated)
			}
			if (len(searched) == 0) != r.empty {
				t.Errorf("the rule matches %d CVEs; want none: %v", len(searched), r.empty)
			}

			draft := mustRule(t, ctx, tdb.Store, orgID, r.logic, r.conditions, nil)
			dry, err := ev.DryRun(ctx, draft.ID, orgID)
			if err != nil || dry == nil {
				t.Fatalf("DryRun: %v, %v", dry, err)
			}
			if dry.Partial || dry.MatchCount != len(searched) {
				t.Errorf("DryRun: partial %v, %d matches, want %d", dry.Partial, dry.MatchCount, len(searched))
			}
			t.Logf("%s: %d CVEs", r.name, len(searched))
		})
	}

	// The package names rule reaches the PyPI foo-bar row through folding, not the
	// npm one, and both lodash rows, with candidate IDs and without.
	searched := search(t, "or", packageNames)
	activated := activationMatches(t, ctx, tdb, ev, orgID, "or", packageNames)
	for _, got := range [][]string{searched, activated} {
		for _, id := range []string{cvePkgPyPIFooBar, cvePkgMixed, cvePkgPyPILodash, cvePkgNpmLodash} {
			if !slices.Contains(got, id) {
				t.Errorf("package names: %s not matched; matched %v", id, got)
			}
		}
		for _, id := range []string{cvePkgNpmFooBar, cvePkgRejected} {
			if slices.Contains(got, id) {
				t.Errorf("package names: %s matched; it must not be", id)
			}
		}
	}
}

// TestProductMatch_AcceptanceCNAThenNVD is design section 15.2's acceptance case
// and section 3.5's steps 1 and 2: a CVE whose CNA record names Node.js, before
// NVD analysis, fires the rule; NVD's analysis then adds nodejs:node.js, the
// material hash changes, and the rule fires a second time.
func TestProductMatch_AcceptanceCNAThenNVD(t *testing.T) {
	// Not parallel: the NVD golden fixtures set an environment variable.
	tdb := testutil.NewTestDB(t)
	ev := newTestEvaluator(t, tdb)
	ctx := context.Background()
	orgID := createTestOrg(t, tdb.DB())
	const cveID = "CVE-2026-31201"

	p := testutil.GoldenPatch(t, "nvd", "CVE-2026-56847")
	if !slices.ContainsFunc(p.CNAAffected, func(a feed.CNAAffected) bool {
		return strings.EqualFold(a.Vendor, "nodejs") && strings.EqualFold(a.Product, "node")
	}) {
		t.Fatalf("golden CVE-2026-56847 has no CNA entry nodejs / node: %+v", p.CNAAffected)
	}
	p.CVEID, p.SourceID = cveID, cveID
	p.CPEMatches, p.AffectedCPEs = nil, nil
	high := "HIGH"
	p.Severity = &high
	p.RawPayload = nil
	if err := merge.Ingest(ctx, tdb.Store, p, "nvd"); err != nil {
		t.Fatalf("merge.Ingest: %v", err)
	}
	var severity, firstHash string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT severity, material_hash FROM cves WHERE cve_id = $1`, cveID).Scan(&severity, &firstHash); err != nil {
		t.Fatalf("read %s: %v", cveID, err)
	}
	if severity != "HIGH" {
		t.Fatalf("severity %q, want HIGH", severity)
	}

	rule := mustRule(t, ctx, tdb.Store, orgID, "and",
		`[{"field":"affected.cpe_product","operator":"eq","value":"nodejs:node.js"},{"field":"severity","operator":"in","value":["critical","high"]}]`, nil)
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime: %v", err)
	}
	if n := countAlertEventsAt(t, tdb.DB(), rule.ID, cveID, firstHash); n != 1 {
		t.Fatalf("%d events at the CNA-only hash, want 1", n)
	}

	nodeCPE := "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"
	p.CPEMatches = []feed.CPEMatch{{CPE: nodeCPE, CPENormalized: nodeCPE, VersionEndExcluding: "24.0.0", Vulnerable: true}}
	p.AffectedCPEs = []feed.AffectedCPE{{CPE: nodeCPE, CPENormalized: nodeCPE}}
	if err := merge.Ingest(ctx, tdb.Store, p, "nvd"); err != nil {
		t.Fatalf("merge.Ingest with the NVD analysis: %v", err)
	}
	var secondHash string
	if err := tdb.DB().QueryRowContext(ctx, `SELECT material_hash FROM cves WHERE cve_id = $1`, cveID).Scan(&secondHash); err != nil {
		t.Fatalf("read %s: %v", cveID, err)
	}
	if secondHash == firstHash {
		t.Fatalf("material_hash unchanged after NVD added an affected CPE")
	}
	if err := ev.EvaluateRealtime(ctx, cveID); err != nil {
		t.Fatalf("EvaluateRealtime: %v", err)
	}
	if n := countAlertEventsAt(t, tdb.DB(), rule.ID, cveID, secondHash); n != 1 {
		t.Errorf("%d events at the hash after NVD analysis, want 1", n)
	}
	if n := countAlertEvents(t, tdb.DB(), rule.ID, cveID); n != 2 {
		t.Errorf("%d events in all, want 2", n)
	}
}

// countAlertEventsAt returns the number of alert_events for (rule, cve) at one material hash.
func countAlertEventsAt(t *testing.T, db *sql.DB, ruleID uuid.UUID, cveID, hash string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		`SELECT count(*) FROM alert_events WHERE rule_id = $1 AND cve_id = $2 AND material_hash = $3`,
		ruleID, cveID, hash).Scan(&n); err != nil {
		t.Fatalf("countAlertEventsAt: %v", err)
	}
	return n
}
