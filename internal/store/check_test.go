// ABOUTME: Integration tests for ReadCheckCandidates: the five version check lookups, enrichment and feed rows.
// ABOUTME: Covers the one-snapshot guarantee and the per-key and per-request limits on rows read.
package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/ecosystem"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// ingestPatch merges patch as source through the real merge pipeline.
func ingestPatch(t *testing.T, tdb *testutil.TestDB, source string, patch feed.CanonicalPatch) {
	t.Helper()
	if err := merge.Ingest(context.Background(), tdb.Store, patch, source); err != nil {
		t.Fatalf("merge.Ingest(%s, %s): %v", source, patch.CVEID, err)
	}
}

// checkOrg creates the org a version check runs in.
func checkOrg(t *testing.T, tdb *testutil.TestDB) uuid.UUID {
	t.Helper()
	return tdb.MustCreateOrg(t, context.Background(), "check-org").ID
}

// readCheck reads keys as the application role with the given limits, failing
// the test on an error.
func readCheck(t *testing.T, tdb *testutil.TestDB, orgID uuid.UUID, keys check.Keys, limits store.CheckLimits,
	after func(string)) (check.Candidates, map[string]check.CVEEnrichment, []check.FeedRow) {
	t.Helper()
	cands, enrichment, feeds, err := tdb.AppStore.ReadCheckCandidatesWith(context.Background(), orgID, keys, limits, after)
	if err != nil {
		t.Fatalf("ReadCheckCandidates: %v", err)
	}
	return cands, enrichment, feeds
}

// productKeys returns the keys check builds for one CPE product item.
func productKeys(part, vendor, product string) check.Keys {
	return check.KeysFor([]check.Item{{Product: &check.ProductRef{Part: part, Vendor: vendor, Product: product}}})
}

// cnaNameKey returns the CNA name key of productKeys with the given whole
// product: the item's own exact name, or "" for a table prefix.
func cnaNameKey(t *testing.T, keys check.Keys, fullProduct string) check.CNANameKey {
	t.Helper()
	for _, k := range keys.CNANames {
		if k.FullProduct == fullProduct {
			return k
		}
	}
	t.Fatalf("no CNA name key with product %q in %+v", fullProduct, keys.CNANames)
	return check.CNANameKey{}
}

// cpeMatch is a vulnerable NVD match on the CPE with the given part:vendor:product.
func cpeMatch(pvp, endExcluding string) feed.CPEMatch {
	cpe := "cpe:2.3:" + pvp + ":*:*:*:*:*:*:*:*"
	return feed.CPEMatch{CPE: cpe, CPENormalized: cpe, VersionEndExcluding: endExcluding, Vulnerable: true}
}

func TestReadCheckCandidates_Packages(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90001", AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: "Lodash", RangeType: "SEMVER", Introduced: "0", Fixed: "4.17.21"},
	}})
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90002", AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: "lodash-es", RangeType: "SEMVER", Introduced: "0", LastAffected: "4.17.20"},
	}})

	keys := check.Keys{Packages: []check.PackageKey{{Ecosystem: "npm", Name: "lodash"}, {Ecosystem: "npm", Name: "underscore"}}}
	orgID := checkOrg(t, tdb)
	cands, _, _ := readCheck(t, tdb, orgID, keys, store.DefaultCheckLimits, nil)

	if len(cands.Packages) != 2 || len(cands.CPEs) != 0 || len(cands.CNANames) != 0 ||
		len(cands.CNAPackageKeys) != 0 || len(cands.CNANear) != 0 {
		t.Fatalf("candidate slots do not match the keys: %+v", cands)
	}
	want := []check.PackageRow{{CVEID: "CVE-2026-90001", Ecosystem: "npm", PackageName: "Lodash", RangeType: "SEMVER",
		Introduced: "0", Fixed: "4.17.21"}}
	if got := cands.Packages[0]; !reflect.DeepEqual(got.Rows, want) || got.Overflow {
		t.Errorf("npm/lodash = %+v, want rows %+v and no overflow", got, want)
	}
	if got := cands.Packages[1]; len(got.Rows) != 0 || got.Overflow {
		t.Errorf("npm/underscore = %+v, want no rows", got)
	}

	// The exported method, which the handler calls, reads the same rows.
	direct, _, _, err := tdb.AppStore.ReadCheckCandidates(context.Background(), orgID, keys)
	if err != nil {
		t.Fatalf("ReadCheckCandidates: %v", err)
	}
	if !reflect.DeepEqual(direct, cands) {
		t.Errorf("ReadCheckCandidates = %+v, want %+v", direct, cands)
	}
}

func TestReadCheckCandidates_CPEPrefix(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	notVulnerable := cpeMatch("a:nodejs:node.js", "1.0.0")
	notVulnerable.Vulnerable = false
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90011", CPEMatches: []feed.CPEMatch{
		cpeMatch("a:nodejs:node.js", "24.22.1"),
		notVulnerable,
		cpeMatch("a:foo:bar", ""),
		cpeMatch("a:foo:barbaz", ""),
		cpeMatch(`a:x:foo\:bar`, ""),
		cpeMatch(`a:x:foo\:barbaz`, ""),
	}})

	keys := check.Keys{CPEPrefixes: []check.CPEKey{
		productKeys("a", "nodejs", "node.js").CPEPrefixes[0],
		productKeys("a", "foo", "bar").CPEPrefixes[0],
		productKeys("a", "x", `foo\:bar`).CPEPrefixes[0],
		productKeys("a", "nodejs", "npm").CPEPrefixes[0],
	}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	node := cpeMatch("a:nodejs:node.js", "24.22.1")
	wantNode := []check.CPERow{{CVEID: "CVE-2026-90011", CPE: node.CPENormalized, VersionEndExcluding: "24.22.1"}}
	if got := cands.CPEs[0].Rows; !reflect.DeepEqual(got, wantNode) {
		t.Errorf("nodejs:node.js rows = %+v, want only the vulnerable row %+v", got, wantNode)
	}
	for i, want := range map[int]string{1: cpeMatch("a:foo:bar", "").CPENormalized, 2: cpeMatch(`a:x:foo\:bar`, "").CPENormalized} {
		rows := cands.CPEs[i].Rows
		if len(rows) != 1 || rows[0].CPE != want {
			t.Errorf("key %+v rows = %+v, want only %s", keys.CPEPrefixes[i], rows, want)
		}
	}
	if rows := cands.CPEs[3].Rows; len(rows) != 0 {
		t.Errorf("nodejs:npm rows = %+v, want none", rows)
	}
}

func TestReadCheckCandidates_CNANames(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	long := strings.Repeat("p", 256)
	runtimeVersions := []feed.CNAVersion{{Version: "9.0.0", LessThan: "9.0.5", Status: "affected", VersionType: "semver"}}
	ingestPatch(t, tdb, "mitre", feed.CanonicalPatch{CVEID: "CVE-2026-90021", CNAAffected: []feed.CNAAffected{
		{Vendor: "Microsoft", Product: ".NET 9.0 runtime", Versions: runtimeVersions},
	}})
	ingestPatch(t, tdb, "mitre", feed.CanonicalPatch{CVEID: "CVE-2026-90022", CNAAffected: []feed.CNAAffected{
		{Vendor: "Acme", Product: "Widget"},
		{Vendor: "Acme", Product: "Widget Pro"},
		{Vendor: "Acme", Product: long + "one"},
		{Vendor: "Acme", Product: long + "two"},
	}})

	keys := check.Keys{CNANames: []check.CNANameKey{
		cnaNameKey(t, productKeys("a", "microsoft", ".net"), ""),
		cnaNameKey(t, productKeys("a", "acme", "widget"), "widget"),
		cnaNameKey(t, productKeys("a", "acme", long+"one"), long+"one"),
		cnaNameKey(t, productKeys("a", "acme", "gizmo"), "gizmo"),
	}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	wantRuntime := []check.CNARow{{CVEID: "CVE-2026-90021", Vendor: "Microsoft", Product: ".NET 9.0 runtime",
		Versions: []check.CNAVersion{{Version: "9.0.0", LessThan: "9.0.5", Status: "affected", VersionType: "semver"}}}}
	if got := cands.CNANames[0].Rows; !reflect.DeepEqual(got, wantRuntime) {
		t.Errorf("prefix microsoft/.net rows = %+v, want %+v", got, wantRuntime)
	}
	for i, want := range map[int]string{1: "Widget", 2: long + "one"} {
		rows := cands.CNANames[i].Rows
		if len(rows) != 1 || rows[0].Product != want || rows[0].Vendor != "Acme" {
			t.Errorf("exact key %d rows = %+v, want only Acme/%s as stored", i, rows, want)
		}
	}
	if rows := cands.CNANames[3].Rows; len(rows) != 0 {
		t.Errorf("acme/gizmo rows = %+v, want none", rows)
	}
}

func TestReadCheckCandidates_CNAPackageKeys(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestPatch(t, tdb, "mitre", feed.CanonicalPatch{CVEID: "CVE-2026-90031", CNAAffected: []feed.CNAAffected{{
		Vendor: "fastify", Product: "fastify", PackageKey: "npm/fastify",
		Versions: []feed.CNAVersion{{Version: "5.0.0", LessThan: "5.12.6", Status: "affected", VersionType: "semver",
			Changes: []feed.CNAVersionChange{{At: "5.10.0", Status: "unaffected"}}}},
	}}})

	keys := check.Keys{CNAPackageKeys: []string{"npm/fastify", "npm/express"}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	rows := cands.CNAPackageKeys[0].Rows
	wantVersions := []check.CNAVersion{{Version: "5.0.0", LessThan: "5.12.6", Status: "affected", VersionType: "semver",
		Changes: []check.CNAChange{{At: "5.10.0", Status: "unaffected"}}}}
	if len(rows) != 1 || rows[0].CVEID != "CVE-2026-90031" || !reflect.DeepEqual(rows[0].Versions, wantVersions) {
		t.Errorf("npm/fastify rows = %+v, want CVE-2026-90031 with versions %+v", rows, wantVersions)
	}
	if rows := cands.CNAPackageKeys[1].Rows; len(rows) != 0 {
		t.Errorf("npm/express rows = %+v, want none", rows)
	}
}

func TestReadCheckCandidates_CNANear(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	// Analysed by NVD only for another vendor: still near the name.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90041",
		CNAAffected: []feed.CNAAffected{{Vendor: "NodeJS", Product: "Node.js runtime"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:other:thing", "")},
	})
	// Analysed by NVD for this vendor: not near.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90042",
		CNAAffected: []feed.CNAAffected{{Vendor: "nodejs", Product: "node-ish"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:nodejs:npm", "")},
	})
	// A product without the fragment: not near.
	ingestPatch(t, tdb, "mitre", feed.CanonicalPatch{CVEID: "CVE-2026-90043",
		CNAAffected: []feed.CNAAffected{{Vendor: "nodejs", Product: "npm"}},
	})

	keys := check.Keys{CNANear: []check.CNANearKey{
		productKeys("a", "nodejs", "node.js").CNANear[0],
		productKeys("a", "acme", "gizmo").CNANear[0],
	}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	want := []check.CNANearRow{{CVEID: "CVE-2026-90041", Vendor: "NodeJS", Product: "Node.js runtime"}}
	if got := cands.CNANear[0].Rows; !reflect.DeepEqual(got, want) {
		t.Errorf("near nodejs/node rows = %+v, want %+v", got, want)
	}
	if rows := cands.CNANear[1].Rows; len(rows) != 0 {
		t.Errorf("near acme/gizmo rows = %+v, want none", rows)
	}
}

// TestReadCheckCandidates_CNANearEverySpelling checks that a nearby-name key is
// lifted by an NVD row under the vendor of any CPE spelling its item reads: an
// nginx:nginx item reads f5:nginx too, so a CVE analysed under f5 is not near.
func TestReadCheckCandidates_CNANearEverySpelling(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	// Analysed by NVD under the other spelling's vendor only: not near.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90044",
		CNAAffected: []feed.CNAAffected{{Vendor: "F5", Product: "NGINX Plus"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:f5:nginx_plus", "")},
	})
	// Analysed by NVD under the item's own vendor only: not near.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90045",
		CNAAffected: []feed.CNAAffected{{Vendor: "F5", Product: "NGINX Agent"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:nginx:agent", "")},
	})
	// Analysed by NVD under neither vendor: near.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90046",
		CNAAffected: []feed.CNAAffected{{Vendor: "F5", Product: "NGINX Controller"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:other:thing", "")},
	})

	orgID := checkOrg(t, tdb)
	for _, vendor := range []string{"nginx", "f5"} {
		keys := check.Keys{CNANear: productKeys("a", vendor, "nginx").CNANear}
		cands, _, _ := readCheck(t, tdb, orgID, keys, store.DefaultCheckLimits, nil)
		want := []check.CNANearRow{{CVEID: "CVE-2026-90046", Vendor: "F5", Product: "NGINX Controller"}}
		if len(cands.CNANear) != 1 || !reflect.DeepEqual(cands.CNANear[0].Rows, want) {
			t.Errorf("%s:nginx nearby rows = %+v, want only %+v", vendor, cands.CNANear, want)
		}
	}
}

// TestReadCheckCandidates_CNANearOwnRanges checks that a nearby-name key is
// lifted only by an NVD row in its own vendor ranges: another key's vendor
// range in the same request lifts nothing.
func TestReadCheckCandidates_CNANearOwnRanges(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	// Analysed by NVD only under the other key's vendor: near the nodejs key.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90047",
		CNAAffected: []feed.CNAAffected{{Vendor: "NodeJS", Product: "Node.js runtime"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:acme:gizmo", "")},
	})
	// Analysed by NVD only under the other key's vendor: near the acme key.
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90048",
		CNAAffected: []feed.CNAAffected{{Vendor: "Acme", Product: "Gizmo Pro"}},
		CPEMatches:  []feed.CPEMatch{cpeMatch("a:nodejs:npm", "")},
	})

	keys := check.Keys{CNANear: []check.CNANearKey{
		productKeys("a", "nodejs", "node.js").CNANear[0],
		productKeys("a", "acme", "gizmo").CNANear[0],
	}}
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	wantNode := []check.CNANearRow{{CVEID: "CVE-2026-90047", Vendor: "NodeJS", Product: "Node.js runtime"}}
	if got := cands.CNANear[0].Rows; !reflect.DeepEqual(got, wantNode) {
		t.Errorf("near nodejs/node rows = %+v, want %+v (an acme range lifts nothing)", got, wantNode)
	}
	wantAcme := []check.CNANearRow{{CVEID: "CVE-2026-90048", Vendor: "Acme", Product: "Gizmo Pro"}}
	if got := cands.CNANear[1].Rows; !reflect.DeepEqual(got, wantAcme) {
		t.Errorf("near acme/gizmo rows = %+v, want %+v (a nodejs range lifts nothing)", got, wantAcme)
	}
}

func TestReadCheckCandidates_StatusEnrichmentAndFeeds(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	high, medium, score, kev := "HIGH", "MEDIUM", 7.5, true
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90051", Status: "REJECTED",
		Severity: &high, CVSSv3Score: &score, InCISAKEV: &kev,
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "left-pad", RangeType: "SEMVER", Introduced: "0"}},
	})
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "UBUNTU-CVE-2026-90052",
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "Ubuntu:24.04:LTS", PackageName: "left-pad", RangeType: "ECOSYSTEM", Introduced: "0"}},
	})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90052", Severity: &medium})
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90053", Severity: &high})

	succeeded := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, state := range []store.FeedSyncState{
		{FeedName: "ghsa", CursorJSON: json.RawMessage(`{"since":"2026-11-09T00:00:00Z"}`), LastSuccessAt: &succeeded},
		{FeedName: "nvd", CursorJSON: json.RawMessage(`{"caught_up":true}`), LastSuccessAt: &succeeded},
		{FeedName: "osv"},
		{FeedName: "mitre", LastSuccessAt: &succeeded},
	} {
		if err := tdb.UpsertFeedSyncState(ctx, state); err != nil {
			t.Fatalf("UpsertFeedSyncState(%s): %v", state.FeedName, err)
		}
	}

	keys := check.Keys{Packages: []check.PackageKey{{Ecosystem: "npm", Name: "left-pad"}, {Ecosystem: "Ubuntu:24.04:LTS", Name: "left-pad"}}}
	cands, enrichment, feeds := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	if rows := cands.Packages[0].Rows; len(rows) != 1 || rows[0].Status != "REJECTED" {
		t.Errorf("npm/left-pad rows = %+v, want one row with status REJECTED as stored", rows)
	}
	if rows := cands.Packages[1].Rows; len(rows) != 1 || rows[0].CVEID != "UBUNTU-CVE-2026-90052" || rows[0].Status != "" {
		t.Errorf("Ubuntu left-pad rows = %+v, want UBUNTU-CVE-2026-90052 with no status", rows)
	}

	wantEnrichment := map[string]check.CVEEnrichment{
		"CVE-2026-90051":        {Severity: &high, CVSSv3Score: &score, InCISAKEV: true},
		"UBUNTU-CVE-2026-90052": {},
		"CVE-2026-90052":        {Severity: &medium},
	}
	if !reflect.DeepEqual(enrichment, wantEnrichment) {
		t.Errorf("enrichment = %s, want %s (advisories read and the CVEs they name, nothing else)",
			describeEnrichment(enrichment), describeEnrichment(wantEnrichment))
	}

	if names := feedNames(feeds); !reflect.DeepEqual(names, []string{"ghsa", "nvd", "osv"}) {
		t.Fatalf("feeds = %v, want ghsa, nvd and osv", names)
	}
	for _, f := range feeds {
		switch f.Name {
		case "ghsa":
			assertCursor(t, f, map[string]any{"since": "2026-11-09T00:00:00Z"})
		case "nvd":
			assertCursor(t, f, map[string]any{"caught_up": true})
		case "osv":
			if f.CursorJSON != nil || f.LastSuccessAt != nil {
				t.Errorf("osv = %+v, want no cursor and no success", f)
			}
			continue
		}
		if f.LastSuccessAt == nil || !f.LastSuccessAt.Equal(succeeded) {
			t.Errorf("%s last success = %v, want %v", f.Name, f.LastSuccessAt, succeeded)
		}
	}
}

// TestReadCheckCandidates_EnrichmentFromCorpus reads exploit data for a real
// seeded CVE with an EPSS score, which merge does not write. Not parallel:
// SeedCorpus sets environment variables.
func TestReadCheckCandidates_EnrichmentFromCorpus(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	testutil.SeedCorpus(t, tdb)

	var (
		cveID, eco, name string
		want             check.CVEEnrichment
		severity         *string
		cvss, epss       *float64
	)
	err := tdb.DB().QueryRowContext(context.Background(), `
		SELECT c.cve_id, p.ecosystem, p.package_name, c.severity, c.cvss_v3_score, c.in_cisa_kev, c.epss_score
		FROM cves c JOIN cve_affected_packages p ON p.cve_id = c.cve_id
		WHERE c.epss_score IS NOT NULL
		ORDER BY c.cve_id LIMIT 1`).Scan(&cveID, &eco, &name, &severity, &cvss, &want.InCISAKEV, &epss)
	if err != nil {
		t.Fatalf("find a seeded CVE with an EPSS score and a package row: %v", err)
	}
	want.Severity, want.CVSSv3Score, want.EPSSScore = severity, cvss, epss

	keys := check.Keys{Packages: []check.PackageKey{{Ecosystem: eco, Name: ecosystem.FoldPackageName(eco, name)}}}
	_, enrichment, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, store.DefaultCheckLimits, nil)

	got, ok := enrichment[cveID]
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("enrichment[%s] = %s, want %s", cveID, describeEnrichment(map[string]check.CVEEnrichment{cveID: got}),
			describeEnrichment(map[string]check.CVEEnrichment{cveID: want}))
	}
}

func TestReadCheckCandidates_KeyLimit(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ranges := func(name string, fixes ...string) []feed.AffectedPackage {
		var out []feed.AffectedPackage
		for _, fix := range fixes {
			out = append(out, feed.AffectedPackage{Ecosystem: "npm", PackageName: name, RangeType: "SEMVER", Introduced: "0", Fixed: fix})
		}
		return out
	}
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90061", AffectedPackages: ranges("aaa", "1.0.0", "2.0.0", "3.0.0")})
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90062", AffectedPackages: ranges("bbb", "1.0.0", "2.0.0")})
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90063", AffectedPackages: ranges("ccc", "1.0.0")})

	keys := check.Keys{Packages: []check.PackageKey{{Ecosystem: "npm", Name: "aaa"}, {Ecosystem: "npm", Name: "bbb"}, {Ecosystem: "npm", Name: "ccc"}}}
	limits := store.DefaultCheckLimits
	limits.KeyRows = 2
	cands, _, _ := readCheck(t, tdb, checkOrg(t, tdb), keys, limits, nil)

	for i, want := range []struct {
		rows     int
		overflow bool
	}{{2, true}, {2, false}, {1, false}} {
		if got := cands.Packages[i]; len(got.Rows) != want.rows || got.Overflow != want.overflow {
			t.Errorf("%s: %d rows, overflow %v; want %d rows, overflow %v",
				keys.Packages[i].Name, len(got.Rows), got.Overflow, want.rows, want.overflow)
		}
	}
}

func TestReadCheckCandidates_RequestRowLimit(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90065",
		AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "aaa", RangeType: "SEMVER", Introduced: "0"}},
		CPEMatches:       []feed.CPEMatch{cpeMatch("a:acme:widget", "")},
		CNAAffected:      []feed.CNAAffected{{Vendor: "acme", Product: "widget"}},
	})
	orgID := checkOrg(t, tdb)
	product := productKeys("a", "acme", "widget")
	keys := check.Keys{
		Packages:    []check.PackageKey{{Ecosystem: "npm", Name: "aaa"}},
		CPEPrefixes: product.CPEPrefixes,
		CNANames:    []check.CNANameKey{cnaNameKey(t, product, "widget")},
	}

	// One row from each of three statements: the limit is over the request.
	limits := store.DefaultCheckLimits
	limits.RequestRows = 3
	readCheck(t, tdb, orgID, keys, limits, nil)

	limits.RequestRows = 2
	_, _, _, err := tdb.AppStore.ReadCheckCandidatesWith(context.Background(), orgID, keys, limits, nil)
	if !errors.Is(err, store.ErrCandidateLimit) {
		t.Errorf("3 rows over a limit of 2: err = %v, want ErrCandidateLimit", err)
	}
}

// statementTracer records how each statement whose SQL contains match ended.
type statementTracer struct {
	match string
	mu    sync.Mutex
	ends  []pgx.TraceQueryEndData
}

type tracedSQLKey struct{}

func (tr *statementTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, tracedSQLKey{}, data.SQL)
}

func (tr *statementTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if sql, _ := ctx.Value(tracedSQLKey{}).(string); strings.Contains(sql, tr.match) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.ends = append(tr.ends, data)
	}
}

func (tr *statementTracer) ended() []pgx.TraceQueryEndData {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return slices.Clone(tr.ends)
}

// tracedStore returns a store on a pool of one application-role connection that
// records how each statement whose SQL contains match ended.
func tracedStore(t *testing.T, tdb *testutil.TestDB, match string) (*store.Store, *statementTracer) {
	t.Helper()
	tracer := &statementTracer{match: match}
	cfg, err := pgxpool.ParseConfig(tdb.AppURL)
	if err != nil {
		t.Fatalf("parse app pool config: %v", err)
	}
	cfg.ConnConfig.DefaultQueryExecMode = store.DefaultQueryExecMode
	cfg.ConnConfig.Tracer = tracer
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool: %v", err)
	}
	t.Cleanup(pool.Close)
	return store.New(pool), tracer
}

// TestReadCheckCandidates_ScanErrorStopsStatement runs a statement of more rows
// than pgx buffers through a lookup whose scan fails on the first row. The
// statement must be stopped, not read to its end when its rows are closed, and
// the store must answer the next read on its one pool connection.
func TestReadCheckCandidates_ScanErrorStopsStatement(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	orgID := checkOrg(t, tdb)
	traced, tracer := tracedStore(t, tdb, "generate_series")

	err := traced.ReadKeyRowsFailingScan(ctx, orgID, "SELECT g FROM generate_series(1, 100000) AS g")
	if !errors.Is(err, store.ErrScanFailed) {
		t.Fatalf("err = %v, want ErrScanFailed", err)
	}
	ends := tracer.ended()
	if len(ends) != 1 {
		t.Fatalf("statement ended %d times, want once: %+v", len(ends), ends)
	}
	if ends[0].Err == nil {
		t.Errorf("statement completed (%s), want it stopped once the scan failed", ends[0].CommandTag)
	}

	if _, _, _, err := traced.ReadCheckCandidatesWith(ctx, orgID, check.Keys{}, store.DefaultCheckLimits, nil); err != nil {
		t.Fatalf("read after the stopped statement: %v", err)
	}
}

// TestReadCheckCandidates_RequestLimitStopsStatement reads a key with more rows
// than pgx buffers, over a request limit of one row. The packages statement must
// be stopped, not read to its end when its rows are closed, and the store must
// answer the next read on its one pool connection.
func TestReadCheckCandidates_RequestLimitStopsStatement(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const ranges = 3000
	pkgs := make([]feed.AffectedPackage, ranges)
	for i := range pkgs {
		pkgs[i] = feed.AffectedPackage{Ecosystem: "npm", PackageName: "many", RangeType: "ECOSYSTEM",
			Introduced: "0", Fixed: fmt.Sprintf("1.0.%d", i)}
	}
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90075", AffectedPackages: pkgs})
	orgID := checkOrg(t, tdb)
	traced, tracer := tracedStore(t, tdb, "cve_affected_packages")

	keys := check.Keys{Packages: []check.PackageKey{{Ecosystem: "npm", Name: "many"}}}
	limits := store.DefaultCheckLimits
	limits.RequestRows = 1
	if _, _, _, err := traced.ReadCheckCandidatesWith(ctx, orgID, keys, limits, nil); !errors.Is(err, store.ErrCandidateLimit) {
		t.Fatalf("%d rows over a limit of 1: err = %v, want ErrCandidateLimit", ranges, err)
	}
	ends := tracer.ended()
	if len(ends) != 1 {
		t.Fatalf("packages statement ended %d times, want once: %+v", len(ends), ends)
	}
	if ends[0].Err == nil {
		t.Errorf("packages statement completed (%s), want it stopped once the limit was passed", ends[0].CommandTag)
	}

	cands, _, _, err := traced.ReadCheckCandidatesWith(ctx, orgID, keys, store.DefaultCheckLimits, nil)
	if err != nil {
		t.Fatalf("read after the stopped statement: %v", err)
	}
	if n := len(cands.Packages[0].Rows); n != ranges {
		t.Errorf("read after the stopped statement: %d rows, want %d", n, ranges)
	}
}

func TestReadCheckCandidates_RequestByteLimit(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	// 14 + 3 + 3 + 6 + 1 + 5 bytes of strings; last_affected and status are empty.
	ingestPatch(t, tdb, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90071", AffectedPackages: []feed.AffectedPackage{
		{Ecosystem: "npm", PackageName: "aaa", RangeType: "SEMVER", Introduced: "0", Fixed: "1.0.0"},
	}})
	ingestPatch(t, tdb, "mitre", feed.CanonicalPatch{CVEID: "CVE-2026-90072", CNAAffected: []feed.CNAAffected{{
		PackageKey: "npm/bbb", Versions: []feed.CNAVersion{{Version: strings.Repeat("9", 600), Status: "affected"}},
	}}})
	orgID := checkOrg(t, tdb)
	read := func(keys check.Keys, requestBytes int) error {
		limits := store.DefaultCheckLimits
		limits.RequestBytes = requestBytes
		_, _, _, err := tdb.AppStore.ReadCheckCandidatesWith(context.Background(), orgID, keys, limits, nil)
		return err
	}

	pkg := check.Keys{Packages: []check.PackageKey{{Ecosystem: "npm", Name: "aaa"}}}
	if err := read(pkg, 32); err != nil {
		t.Errorf("32 bytes at a limit of 32: %v", err)
	}
	if err := read(pkg, 31); !errors.Is(err, store.ErrCandidateLimit) {
		t.Errorf("32 bytes over a limit of 31: err = %v, want ErrCandidateLimit", err)
	}
	// The versions array alone is over 600 bytes; its CVE ID is 14.
	if err := read(check.Keys{CNAPackageKeys: []string{"npm/bbb"}}, 500); !errors.Is(err, store.ErrCandidateLimit) {
		t.Errorf("a versions array over a limit of 500: err = %v, want ErrCandidateLimit", err)
	}
}

// TestReadCheckCandidates_OneSnapshot commits a merge and a feed cursor change
// from another connection after the first statement, and expects every later
// statement to see the state from before them.
// TestWithOrgSnapshotTx_Mode checks that the version check's transaction is
// read-only and REPEATABLE READ, which make its statements one snapshot.
func TestWithOrgSnapshotTx_Mode(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	orgID := checkOrg(t, tdb)

	var readOnly, isolation string
	err := tdb.AppStore.WithOrgSnapshotTx(ctx, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SHOW transaction_read_only").Scan(&readOnly); err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, "SHOW transaction_isolation").Scan(&isolation)
	})
	if err != nil {
		t.Fatalf("WithOrgSnapshotTx: %v", err)
	}
	if readOnly != "on" || isolation != "repeatable read" {
		t.Errorf("transaction_read_only = %q, transaction_isolation = %q; want on, repeatable read", readOnly, isolation)
	}
}

func TestReadCheckCandidates_OneSnapshot(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	high, low := "HIGH", "LOW"
	pkg := []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "aaa", RangeType: "SEMVER", Introduced: "0", Fixed: "1.0.0"}}
	ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90081", Severity: &high, AffectedPackages: pkg})
	if err := tdb.UpsertFeedSyncState(ctx, store.FeedSyncState{FeedName: "nvd", CursorJSON: json.RawMessage(`{"caught_up":false}`)}); err != nil {
		t.Fatalf("UpsertFeedSyncState: %v", err)
	}
	orgID := checkOrg(t, tdb)
	keys := check.Keys{
		Packages:    []check.PackageKey{{Ecosystem: "npm", Name: "aaa"}},
		CPEPrefixes: productKeys("a", "acme", "gizmo").CPEPrefixes,
	}

	var statements []string
	after := func(name string) {
		if len(statements) == 0 {
			ingestPatch(t, tdb, "nvd", feed.CanonicalPatch{CVEID: "CVE-2026-90081", Severity: &low, AffectedPackages: pkg,
				CPEMatches: []feed.CPEMatch{cpeMatch("a:acme:gizmo", "2.0.0")}})
			if err := tdb.UpsertFeedSyncState(ctx, store.FeedSyncState{FeedName: "nvd", CursorJSON: json.RawMessage(`{"caught_up":true}`)}); err != nil {
				t.Fatalf("UpsertFeedSyncState: %v", err)
			}
		}
		statements = append(statements, name)
	}
	cands, enrichment, feeds := readCheck(t, tdb, orgID, keys, store.DefaultCheckLimits, after)

	if want := []string{"packages", "cpe", "enrichment", "feeds"}; !slices.Equal(statements, want) {
		t.Errorf("statements run = %v, want %v (the empty CNA lookups skipped)", statements, want)
	}
	if rows := cands.CPEs[0].Rows; len(rows) != 0 {
		t.Errorf("CPE rows = %+v, want none: the CPE row was committed after the snapshot", rows)
	}
	if e := enrichment["CVE-2026-90081"]; e.Severity == nil || *e.Severity != high {
		t.Errorf("enrichment = %s, want severity HIGH from the snapshot", describeEnrichment(enrichment))
	}
	if len(feeds) != 1 {
		t.Fatalf("feeds = %+v, want the nvd row", feeds)
	}
	assertCursor(t, feeds[0], map[string]any{"caught_up": false})

	// The changes were committed: a later read sees them.
	cands, enrichment, feeds = readCheck(t, tdb, orgID, keys, store.DefaultCheckLimits, nil)
	if e := enrichment["CVE-2026-90081"]; len(cands.CPEs[0].Rows) != 1 || e.Severity == nil || *e.Severity != low || len(feeds) != 1 {
		t.Fatalf("second read = %+v, %s, %+v; want the committed CPE row, LOW and the nvd row",
			cands.CPEs, describeEnrichment(enrichment), feeds)
	}
	assertCursor(t, feeds[0], map[string]any{"caught_up": true})
}

func TestReadCheckCandidates_NoKeys(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	var statements []string
	cands, enrichment, _ := readCheck(t, tdb, checkOrg(t, tdb), check.Keys{}, store.DefaultCheckLimits,
		func(name string) { statements = append(statements, name) })
	if !slices.Equal(statements, []string{"feeds"}) {
		t.Errorf("statements run = %v, want only feeds", statements)
	}
	if len(cands.Packages)+len(cands.CPEs)+len(cands.CNANames)+len(cands.CNAPackageKeys)+len(cands.CNANear) != 0 || len(enrichment) != 0 {
		t.Errorf("read %+v and %+v for no keys, want nothing", cands, enrichment)
	}
}

func feedNames(feeds []check.FeedRow) []string {
	names := make([]string, 0, len(feeds))
	for _, f := range feeds {
		names = append(names, f.Name)
	}
	slices.Sort(names)
	return names
}

// assertCursor compares a feed row's cursor as JSON, since jsonb does not keep
// the text it was given.
func assertCursor(t *testing.T, f check.FeedRow, want map[string]any) {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(f.CursorJSON, &got); err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("%s cursor = %s (%v), want %v", f.Name, f.CursorJSON, err, want)
	}
}

// describeEnrichment prints enrichment with its pointers followed.
func describeEnrichment(m map[string]check.CVEEnrichment) string {
	var b strings.Builder
	for _, id := range slices.Sorted(maps.Keys(m)) {
		e := m[id]
		out, _ := json.Marshal(e)
		b.WriteString(id + ":" + string(out) + " ")
	}
	return b.String()
}
