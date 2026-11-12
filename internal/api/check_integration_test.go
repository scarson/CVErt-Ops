// ABOUTME: End-to-end version check cases: one subtest per row of design section 12's test data table.
// ABOUTME: Data comes from the golden corpus (SeedCorpus) or from targeted patches merged through merge.Ingest.
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/scarson/cvert-ops/internal/check"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// The rows of design section 12 that the check package's table tests also
// cover are run here end to end as well; each such subtest names its unit test.

// checkCursors are cursors that mark each feed's first walk as finished.
var checkCursors = map[string]string{
	"ghsa": `{"since":"2026-11-01T00:00:00Z"}`,
	"osv":  `{"last_modified":"2026-11-01T00:00:00Z"}`,
	"nvd":  `{"caught_up":true}`,
}

// setCheckCursors writes a finished walk and a recent success for each named feed.
func setCheckCursors(t *testing.T, f *securityFixture, feeds ...string) {
	t.Helper()
	now := time.Now()
	for _, name := range feeds {
		if err := f.db.UpsertFeedSyncState(context.Background(), store.FeedSyncState{
			FeedName: name, CursorJSON: json.RawMessage(checkCursors[name]), LastSuccessAt: &now,
		}); err != nil {
			t.Fatalf("UpsertFeedSyncState %s: %v", name, err)
		}
	}
}

// newCompleteCheckFixture is a fixture whose ghsa, osv and nvd feeds are complete,
// so a clean answer is not turned into data_incomplete.
func newCompleteCheckFixture(t *testing.T) *securityFixture {
	t.Helper()
	f := newSecurityFixture(t)
	setCheckCursors(t, f, "ghsa", "osv", "nvd")
	return f
}

// ingestCheckPatch merges patch as source through the real merge pipeline.
func ingestCheckPatch(t *testing.T, f *securityFixture, source string, patch feed.CanonicalPatch) {
	t.Helper()
	if err := merge.Ingest(context.Background(), f.db.Store, patch, source); err != nil {
		t.Fatalf("merge.Ingest(%s, %s): %v", source, patch.CVEID, err)
	}
}

// cnaFromCVE5 parses a CVE 5 containers.cna.affected[] array as the MITRE and
// NVD adapters do, so package keys and versions come from the production parser.
func cnaFromCVE5(t *testing.T, cveID, affected string) []feed.CNAAffected {
	t.Helper()
	entries := feed.ParseCNAAffected(json.RawMessage(affected), cveID)
	if len(entries) == 0 {
		t.Fatalf("%s: CNA affected array parsed to no entries", cveID)
	}
	return entries
}

// mitreCNAPatch is a MITRE record holding only CNA affected data.
func mitreCNAPatch(t *testing.T, cveID, affected string) feed.CanonicalPatch {
	t.Helper()
	return feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "PUBLISHED", CNAAffected: cnaFromCVE5(t, cveID, affected)}
}

// nvdCPEPatch is an analysed NVD record holding the given vulnerable CPE matches.
func nvdCPEPatch(cveID string, matches ...feed.CPEMatch) feed.CanonicalPatch {
	return feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "Analyzed", CPEMatches: matches}
}

// vulnerableCPE is a vulnerable NVD match on part:vendor:product with any
// version, bounded by [start, endExcluding); an empty bound is absent.
func vulnerableCPE(pvp, start, endExcluding string) feed.CPEMatch {
	cpe := "cpe:2.3:" + pvp + ":*:*:*:*:*:*:*:*"
	return feed.CPEMatch{CPE: cpe, CPENormalized: cpe, VersionStartIncluding: start,
		VersionEndExcluding: endExcluding, Vulnerable: true}
}

// rejectedByMITRE is the MITRE record of a rejected CVE.
func rejectedByMITRE(cveID string) feed.CanonicalPatch {
	return feed.CanonicalPatch{CVEID: cveID, SourceID: cveID, Status: "REJECTED", IsWithdrawn: true}
}

// cpeItem is a CPE-form request item for an application vendor:product.
func cpeItem(vendorProduct, version string) string {
	return fmt.Sprintf(`{"cpe":"cpe:2.3:a:%s:*:*:*:*:*:*:*:*","version":%q}`, vendorProduct, version)
}

// pkgItem is an ecosystem-form request item.
func pkgItem(ecosystem, name, version string) string {
	return fmt.Sprintf(`{"ecosystem":%q,"name":%q,"version":%q}`, ecosystem, name, version)
}

// checkItems posts items as a viewer and returns the response.
func checkItems(t *testing.T, f *securityFixture, items ...string) CheckResults {
	t.Helper()
	results := mustCheck(t, f, `{"items":[`+strings.Join(items, ",")+`]}`)
	if len(results.Results) != len(items) {
		t.Fatalf("got %d results for %d items", len(results.Results), len(items))
	}
	return results
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// describeAdvisories lists an item's advisories as "id verdict/reason/fixed".
func describeAdvisories(res CheckItemResult) string {
	parts := make([]string, 0, len(res.Advisories))
	for _, a := range res.Advisories {
		parts = append(parts, fmt.Sprintf("%s %s/%s/%s", a.AdvisoryID, a.Verdict, strOrEmpty(a.Reason), strOrEmpty(a.FixedVersion)))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// wantItem asserts an item's status and item-level reason ("" for null).
func wantItem(t *testing.T, res CheckItemResult, status, reason string) {
	t.Helper()
	if res.Status != status || strOrEmpty(res.Reason) != reason {
		t.Errorf("item %d: status %q, reason %q; want %q, %q (counts %+v, advisories %s)",
			res.Index, res.Status, strOrEmpty(res.Reason), status, reason, res.Counts, describeAdvisories(res))
	}
}

// findAdvisory returns the listed advisory with the given ID, or nil.
func findAdvisory(res CheckItemResult, id string) *CheckAdvisory {
	for i := range res.Advisories {
		if res.Advisories[i].AdvisoryID == id {
			return &res.Advisories[i]
		}
	}
	return nil
}

// wantAdvisory asserts that advisory id is listed with the given verdict, reason
// and fixed version ("" for null), and returns it.
func wantAdvisory(t *testing.T, res CheckItemResult, id, verdict, reason, fixed string) *CheckAdvisory {
	t.Helper()
	a := findAdvisory(res, id)
	if a == nil {
		t.Fatalf("item %d: advisory %s not listed; status %q, advisories %s", res.Index, id, res.Status, describeAdvisories(res))
	}
	if a.Verdict != verdict || strOrEmpty(a.Reason) != reason || strOrEmpty(a.FixedVersion) != fixed {
		t.Errorf("item %d: %s = %s/%s/%s, want %s/%s/%s", res.Index, id,
			a.Verdict, strOrEmpty(a.Reason), strOrEmpty(a.FixedVersion), verdict, reason, fixed)
	}
	if (a.FixedVersion == nil) != (a.FixMajor == nil) {
		t.Errorf("item %d: %s fixed_version %v with fix_major %v", res.Index, id, a.FixedVersion, a.FixMajor)
	}
	return a
}

// wantNoAdvisory asserts that advisory id is not listed.
func wantNoAdvisory(t *testing.T, res CheckItemResult, id string) {
	t.Helper()
	if findAdvisory(res, id) != nil {
		t.Errorf("item %d: advisory %s listed, want it absent: %s", res.Index, id, describeAdvisories(res))
	}
}

// answerOf is an item's answer without its position: status, reason, counts and
// the listed advisories, as JSON.
func answerOf(t *testing.T, res CheckItemResult) string {
	t.Helper()
	res.Index, res.ID = 0, nil
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(b)
}

// applyEPSSScores runs the EPSS adapter against a served scores file holding
// the given CVE scores, as the EPSS feed writes them.
func applyEPSSScores(t *testing.T, f *securityFixture, scores map[string]string) {
	t.Helper()
	var csv strings.Builder
	csv.WriteString("#model_version:v2025.03.14,score_date:2026-11-09T12:55:00Z\ncve,epss,percentile\n")
	for _, id := range slices.Sorted(maps.Keys(scores)) {
		fmt.Fprintf(&csv, "%s,%s,0.99\n", id, scores[id])
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(csv.String())); err != nil {
		t.Fatalf("gzip scores: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip scores: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(gz.Bytes())
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: testutil.NewURLRewriteTransport("https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport)}
	if _, err := epss.New(client).Apply(context.Background(), f.db.DB(), nil); err != nil {
		t.Fatalf("EPSS Apply: %v", err)
	}
}

// The distro acceptance example (design section 6): the three real OSV records
// in the golden archive for php8.5 on Ubuntu 26.04 LTS.
const (
	ubuntuPHPAdvisory1 = "UBUNTU-CVE-2026-109618"
	ubuntuPHPAdvisory2 = "UBUNTU-CVE-2026-109619"
	ubuntuPHPNotice    = "USN-8948-1"
	ubuntuPHPFix       = "8.5.4-0ubuntu1.5"
)

// TestCheckIntegration_GoldenCorpus covers the rows whose data is the golden
// corpus, with every feed's walk finished. The two CVEs of the distro example
// also get the KEV and EPSS data the requirement records for them. SeedCorpus
// sets an environment variable, so the test itself cannot run in parallel. Its
// subtests share one server, which runs at most maxConcurrentChecks checks at
// once, so they run one after another.
func TestCheckIntegration_GoldenCorpus(t *testing.T) {
	f := newCompleteCheckFixture(t)
	testutil.SeedCorpus(t, f.db)
	kev := true
	for _, id := range []string{"CVE-2026-109618", "CVE-2026-109619"} {
		ingestCheckPatch(t, f, "kev", feed.CanonicalPatch{CVEID: id, SourceID: id, InCISAKEV: &kev, ExploitAvailable: &kev})
	}
	applyEPSSScores(t, f, map[string]string{"CVE-2026-109618": "0.91", "CVE-2026-109619": "0.42"})

	const nodeCVE = "CVE-2026-111497"

	t.Run("Node, affected", func(t *testing.T) {
		res := checkItems(t, f, cpeItem("nodejs:node.js", "24.22.0")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		a := wantAdvisory(t, res, nodeCVE, check.VerdictAffected, "", "24.22.1")
		if strOrEmpty(a.FixMajor) != "same" {
			t.Errorf("fix_major = %v, want same", a.FixMajor)
		}
		want := CheckMatchedRange{Evidence: "nvd_cpe", CPE: "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*", Introduced: "23.0.0", Fixed: "24.22.1"}
		if !slices.Contains(a.MatchedRanges, want) {
			t.Errorf("matched_ranges = %+v, want %+v among them", a.MatchedRanges, want)
		}
	})

	t.Run("Node, fixed", func(t *testing.T) {
		results := checkItems(t, f, cpeItem("nodejs:node.js", "24.22.1"))
		res := results.Results[0]
		wantItem(t, res, check.StatusNotAffected, "")
		wantNoAdvisory(t, res, nodeCVE)
		if res.Counts.NotAffected == 0 || !res.DataComplete || !results.DataComplete {
			t.Errorf("counts %+v, data_complete %v (response %v); want advisories counted as not affected on complete data",
				res.Counts, res.DataComplete, results.DataComplete)
		}
	})

	t.Run(".NET branches", func(t *testing.T) {
		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.21")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		wantAdvisory(t, res, nodeCVE, check.VerdictAffected, "", "9.0.22")
	})

	t.Run("Distro", func(t *testing.T) {
		results := checkItems(t, f,
			pkgItem("Ubuntu:26.04:LTS", "php8.5", "8.5.4-0ubuntu1.4"),
			`{"purl":"pkg:deb/ubuntu/php8.5@8.5.4-0ubuntu1.4?distro=ubuntu-26.04"}`)
		res := results.Results[0]
		wantItem(t, res, check.StatusAffected, "")
		if res.Counts.Affected != 3 || len(res.Advisories) != 3 {
			t.Errorf("counts %+v with %d advisories, want the three records affected", res.Counts, len(res.Advisories))
		}
		for id, cves := range map[string][]string{
			ubuntuPHPAdvisory1: {"CVE-2026-109618"},
			ubuntuPHPAdvisory2: {"CVE-2026-109619"},
			ubuntuPHPNotice:    {},
		} {
			a := wantAdvisory(t, res, id, check.VerdictAffected, "", ubuntuPHPFix)
			if !slices.Equal(a.CVEIDs, cves) {
				t.Errorf("%s cve_ids = %v, want %v", id, a.CVEIDs, cves)
			}
		}
		if got, want := answerOf(t, results.Results[1]), answerOf(t, res); got != want {
			t.Errorf("purl form answered differently from the ecosystem form:\n got: %s\nwant: %s", got, want)
		}
	})

	t.Run("Distro, fixed", func(t *testing.T) {
		res := checkItems(t, f, pkgItem("Ubuntu:26.04:LTS", "php8.5", ubuntuPHPFix)).Results[0]
		wantItem(t, res, check.StatusNotAffected, "")
		if res.Counts.NotAffected != 3 {
			t.Errorf("counts %+v, want the three records not affected", res.Counts)
		}
	})

	t.Run("Distro, wrong name", func(t *testing.T) {
		results := checkItems(t, f,
			pkgItem("Ubuntu:26.04:LTS", "php", "8.5.4-0ubuntu1.4"),
			pkgItem("Ubuntu:26.04:LTS", "php8.5-cli", "8.5.4-0ubuntu1.4"))
		for _, res := range results.Results {
			wantItem(t, res, check.StatusCannotEvaluate, "distro_package_not_found")
		}
	})

	t.Run("Multi-branch package", func(t *testing.T) {
		// DRUPAL-CORE-2018-002 is stored under its alias CVE-2018-7600, with ranges
		// [8.0.0, 8.3.9), [8.4.0, 8.4.6) and [8.5.0, 8.5.1).
		res := checkItems(t, f, pkgItem("Packagist", "drupal/core", "8.4.2")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		wantAdvisory(t, res, "CVE-2018-7600", check.VerdictAffected, "", "8.4.6")
	})

	t.Run("No comparator", func(t *testing.T) {
		res := checkItems(t, f, pkgItem("Root:Debian:12", "rootio-linux", "6.1.159-1.root.io.1")).Results[0]
		wantItem(t, res, check.StatusCannotEvaluate, "unknown_version_scheme")
		wantAdvisory(t, res, "ROOT-OS-DEBIAN-12-CVE-2025-40110", check.VerdictCannotEvaluate, "unknown_version_scheme", "")
	})

	t.Run("CNA only", func(t *testing.T) {
		results := checkItems(t, f, cpeItem("fastify:fastify", "5.12.3"), cpeItem("fastify:fastify", "5.12.6"))
		wantItem(t, results.Results[0], check.StatusAffected, "")
		wantAdvisory(t, results.Results[0], "CVE-2026-107832", check.VerdictAffected, "", "5.12.6")
		wantItem(t, results.Results[1], check.StatusUnresolved, "")
		wantAdvisory(t, results.Results[1], "CVE-2026-107832", check.VerdictCannotEvaluate, "cna_cannot_clear", "")
	})

	t.Run("CNA package identity", func(t *testing.T) {
		results := checkItems(t, f, pkgItem("npm", "fastify", "5.12.3"), `{"purl":"pkg:npm/fastify@5.12.6"}`)
		wantItem(t, results.Results[0], check.StatusAffected, "")
		a := wantAdvisory(t, results.Results[0], "CVE-2026-107832", check.VerdictAffected, "", "5.12.6")
		if len(a.MatchedRanges) != 1 || a.MatchedRanges[0].Evidence != "cna" {
			t.Errorf("matched_ranges = %+v, want the CNA range", a.MatchedRanges)
		}
		wantItem(t, results.Results[1], check.StatusUnresolved, "")
		wantAdvisory(t, results.Results[1], "CVE-2026-107832", check.VerdictCannotEvaluate, "cna_cannot_clear", "")
	})

	t.Run("Fix on another major line", func(t *testing.T) {
		results := checkItems(t, f, cpeItem("nodejs:node.js", "20.0.0"), cpeItem("nodejs:node.js", "23.1.0"))
		for i, fixed := range []string{"22.23.4", "24.22.1"} {
			a := wantAdvisory(t, results.Results[i], nodeCVE, check.VerdictAffected, "", fixed)
			if strOrEmpty(a.FixMajor) != "different" {
				t.Errorf("item %d: fix_major = %v, want different", i, a.FixMajor)
			}
		}
	})

	t.Run("v prefix", func(t *testing.T) {
		results := checkItems(t, f, cpeItem("nodejs:node.js", "v24.22.0"), cpeItem("nodejs:node.js", "24.22.0"))
		if got, want := answerOf(t, results.Results[0]), answerOf(t, results.Results[1]); got != want {
			t.Errorf("v24.22.0 answered differently from 24.22.0:\n got: %s\nwant: %s", got, want)
		}
		if c := results.Results[0].Component; c == nil || c.Version != "24.22.0" {
			t.Errorf("component = %+v, want version 24.22.0", c)
		}
	})

	t.Run("Exploit data on a distro record", func(t *testing.T) {
		res := checkItems(t, f, pkgItem("Ubuntu:26.04:LTS", "php8.5", "8.5.4-0ubuntu1.4")).Results[0]
		for id, epssScore := range map[string]float64{ubuntuPHPAdvisory1: 0.91, ubuntuPHPAdvisory2: 0.42} {
			a := wantAdvisory(t, res, id, check.VerdictAffected, "", ubuntuPHPFix)
			if a.InCISAKEV == nil || !*a.InCISAKEV {
				t.Errorf("%s in_cisa_kev = %v, want true from its CVE", id, a.InCISAKEV)
			}
			if a.EPSSScore == nil || *a.EPSSScore != epssScore {
				t.Errorf("%s epss_score = %v, want %v from its CVE", id, a.EPSSScore, epssScore)
			}
		}
		notice := wantAdvisory(t, res, ubuntuPHPNotice, check.VerdictAffected, "", ubuntuPHPFix)
		if notice.InCISAKEV != nil || notice.EPSSScore != nil {
			t.Errorf("%s in_cisa_kev %v, epss_score %v; want both null: it names no CVE", ubuntuPHPNotice, notice.InCISAKEV, notice.EPSSScore)
		}
	})
}

// TestCheckIntegration_GoldenCorpusNoCursors covers the row whose data is the
// golden corpus with no feed cursors written. SeedCorpus sets an environment
// variable, so the test cannot run in parallel.
func TestCheckIntegration_GoldenCorpusNoCursors(t *testing.T) {
	f := newSecurityFixture(t)
	testutil.SeedCorpus(t, f.db)

	t.Run("Same, data incomplete", func(t *testing.T) {
		results := checkItems(t, f, cpeItem("nodejs:node.js", "24.22.1"))
		res := results.Results[0]
		wantItem(t, res, check.StatusCannotEvaluate, "data_incomplete")
		if res.DataComplete || results.DataComplete {
			t.Errorf("data_complete = %v (response %v), want false", res.DataComplete, results.DataComplete)
		}
		if len(results.Feeds) != 1 || results.Feeds[0].Name != "nvd" || results.Feeds[0].Complete {
			t.Errorf("feeds = %+v, want nvd incomplete", results.Feeds)
		}
	})
}

// Real CNA affected arrays, read from cveawg.mitre.org on 2026-11-10.
const (
	// CVE-2024-7347, the NGINX Open Source entry. The record's NGINX Plus entry
	// is left out: as a nearby name it makes the advisory cna_name_uncertain
	// whatever the Open Source entry says, which would hide what this row tests.
	cna7347NGINX = `[{"vendor":"F5","product":"NGINX Open Source","defaultStatus":"unknown","versions":[
		{"status":"affected","version":"1.5.13","lessThan":"*","changes":[
			{"at":"1.26.2","status":"unaffected"},{"at":"1.27.1","status":"unaffected"}],"versionType":"semver"}]}]`

	// CVE-2026-70007, the whole array.
	cna70007 = `[
		{"vendor":"Microsoft","product":".NET 10.0 runtime","versions":[{"version":"10.0.0","lessThan":"10.0.13","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":".NET 11.0 runtime","versions":[{"version":"11.0.0","lessThan":"11.0.0-rc.2","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":".NET 8.0 runtime","versions":[{"version":"8.0.0","lessThan":"8.0.32","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":".NET 9.0 runtime","versions":[{"version":"9.0.0","lessThan":"9.0.21","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 3.5","versions":[{"version":"3.5.0","lessThan":"2.0.50727.8987 AND 3.0.30729.8982","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 3.5 AND 4.6.2/4.7/4.7.1/4.7.2","versions":[{"version":"3.0.0.0","lessThan":"2.0.50727.8987 AND 3.0.30729.8982 AND 4.7.4150.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 3.5 AND 4.7.2","versions":[{"version":"4.7.0","lessThan":"2.0.50727.9073 AND 3.0.30729.9070 AND 4.7.4150.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 3.5 AND 4.8","versions":[{"version":"4.8.0","lessThan":"2.0.50727.9073 AND 3.0.30729.9070 AND 4.8.4811.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 3.5 AND 4.8.1","versions":[{"version":"4.8.1","lessThan":"2.0.50727.9188 AND 3.0.30729.9171 AND 4.8.9363.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 4.6.2/4.7/4.7.1/4.7.2","versions":[{"version":"4.7.0","lessThan":"4.7.4150.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 4.8","versions":[{"version":"4.8.0","lessThan":"4.8.4811.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft .NET Framework 4.8.1","versions":[{"version":"4.8.0.0","lessThan":"4.8.9363.0","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft Visual Studio 2022 version 17.14","versions":[{"version":"17.14.0","lessThan":"17.14.42","versionType":"custom","status":"affected"}]},
		{"vendor":"Microsoft","product":"Microsoft Visual Studio 2026 version 18.10","versions":[{"version":"18.10.0","lessThan":"18.10.4","versionType":"custom","status":"affected"}]}]`

	// CVE-2026-70007, its Microsoft .NET Framework 4.8 entry alone.
	cna70007Framework48 = `[{"vendor":"Microsoft","product":"Microsoft .NET Framework 4.8","versions":[
		{"version":"4.8.0","lessThan":"4.8.4811.0","versionType":"custom","status":"affected"}]}]`

	// An ASP.NET Core entry in the shape of Microsoft's CNA records. ASP.NET Core
	// ships inside the .NET SDK and shared runtime, so it stays a nearby name of
	// microsoft:.net.
	cnaASPNETCore = `[{"vendor":"Microsoft","product":"ASP.NET Core 9.0","versions":[
		{"version":"9.0.0","lessThan":"9.0.11","versionType":"semver","status":"affected"}]}]`

	// CVE-2024-27980, the whole array.
	cna27980 = `[{"vendor":"NodeJS","product":"Node","defaultStatus":"unaffected","versions":[
		{"versionType":"semver","version":"4.0","status":"affected","lessThan":"4.*"},
		{"versionType":"semver","version":"5.0","status":"affected","lessThan":"5.*"},
		{"versionType":"semver","version":"6.0","status":"affected","lessThan":"6.*"},
		{"versionType":"semver","version":"7.0","status":"affected","lessThan":"7.*"},
		{"versionType":"semver","version":"8.0","status":"affected","lessThan":"8.*"},
		{"versionType":"semver","version":"9.0","status":"affected","lessThan":"9.*"},
		{"versionType":"semver","version":"10.0","status":"affected","lessThan":"10.*"},
		{"versionType":"semver","version":"11.0","status":"affected","lessThan":"11.*"},
		{"versionType":"semver","version":"12.0","status":"affected","lessThan":"12.*"},
		{"versionType":"semver","version":"13.0","status":"affected","lessThan":"13.*"},
		{"versionType":"semver","version":"14.0","status":"affected","lessThan":"14.*"},
		{"versionType":"semver","version":"15.0","status":"affected","lessThan":"15.*"},
		{"versionType":"semver","version":"16.0","status":"affected","lessThan":"16.*"},
		{"versionType":"semver","version":"17.0","status":"affected","lessThan":"17.*"},
		{"versionType":"semver","version":"18.0","status":"affected","lessThan":"18.20.2"},
		{"versionType":"semver","version":"19.0","status":"affected","lessThan":"19.*"},
		{"versionType":"semver","version":"20.0","status":"affected","lessThan":"20.12.2"},
		{"versionType":"semver","version":"21.0","status":"affected","lessThan":"21.7.3"}]}]`
)

// acmeCNA is a CNA affected array with one acme entry holding the given CVE 5
// versions[] elements.
func acmeCNA(product, versions string) string {
	return fmt.Sprintf(`[{"vendor":"acme","product":%q,"versions":[%s]}]`, product, versions)
}

// TestCheckIntegration_TargetedPatches covers the rows whose data is a targeted
// patch, or no data at all. Each subtest has its own database.
func TestCheckIntegration_TargetedPatches(t *testing.T) {
	t.Parallel()

	t.Run("Retracted", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90101"
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: cve, SourceID: cve, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "npm", PackageName: "retracted-pkg", RangeType: "SEMVER", Introduced: "0", Fixed: "2.0.0"}}})
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:retracted", "1.0", "2.0")))
		ingestCheckPatch(t, f, "mitre", rejectedByMITRE(cve))

		results := checkItems(t, f, pkgItem("npm", "retracted-pkg", "1.0.0"), cpeItem("acme:retracted", "1.5"))
		for _, res := range results.Results {
			wantItem(t, res, check.StatusNoAdvisoryFound, "")
			wantNoAdvisory(t, res, cve)
			if !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{Retracted: 1})) {
				t.Errorf("item %d: counts %+v, want one retracted", res.Index, res.Counts)
			}
		}
	})

	t.Run("CNA must not clear", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		// The MITRE record alone: NVD's [26.0.0, 26.5.0] row, which reports 26.4.0
		// affected, is absent. The CNA states only 26.5.0 with default unaffected.
		ingestCheckPatch(t, f, "mitre", testutil.GoldenPatch(t, "mitre", "CVE-2026-56847"))

		res := checkItems(t, f, cpeItem("nodejs:node.js", "26.4.0")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, "CVE-2026-56847", check.VerdictCannotEvaluate, "cna_cannot_clear", "")
	})

	t.Run("changes[] must not clear", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2024-7347", cna7347NGINX))

		res := checkItems(t, f, cpeItem("f5:nginx", "1.27.0")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, "CVE-2024-7347", check.VerdictCannotEvaluate, "cna_indeterminate", "")
	})

	t.Run("Wildcard blocks NVD's answer", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2024-27980"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, cna27980))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve,
			vulnerableCPE("a:nodejs:node.js", "18.0.0", "18.20.2"),
			vulnerableCPE("a:nodejs:node.js", "20.0.0", "20.12.2"),
			vulnerableCPE("a:nodejs:node.js", "21.0.0", "21.7.3")))

		res := checkItems(t, f, cpeItem("nodejs:node.js", "12.22.12")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "cna_indeterminate", "")
	})

	t.Run("Wildcard runs to the end of its line", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90104"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1.0.0","lessThan":"2.*","status":"affected","versionType":"semver"}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "0.1.0", "0.5.0")))

		results := checkItems(t, f, cpeItem("acme:widget", "1.5.0"), cpeItem("acme:widget", "3.0.0"))
		wantItem(t, results.Results[0], check.StatusUnresolved, "")
		wantAdvisory(t, results.Results[0], cve, check.VerdictCannotEvaluate, "cna_indeterminate", "")
		// Above the line the wildcard names, the CNA makes no statement, so NVD's
		// rows answer.
		wantItem(t, results.Results[1], check.StatusNotAffected, "")
	})

	t.Run("A step to affected is kept", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		// CVE-2021-44228 as the golden MITRE archive holds it: Apache Log4j2 from
		// 2.0-beta9, steps to unaffected at 2.3.1 and 2.12.2, to affected at 2.4
		// and 2.13.0, and to unaffected at 2.15.0.
		ingestCheckPatch(t, f, "mitre", testutil.GoldenPatch(t, "mitre", "CVE-2021-44228"))
		// An entry first unaffected, with a step to affected at 2.0.
		const stepped = "CVE-2026-90106"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, stepped, acmeCNA("stepper",
			`{"version":"1.0","lessThan":"3.0","status":"unaffected","changes":[{"at":"2.0","status":"affected"},{"at":"2.5","status":"unaffected"}]}`)))

		results := checkItems(t, f,
			cpeItem("apache_software_foundation:apache_log4j2", "2.14.0"), cpeItem("acme:stepper", "2.2"))
		wantItem(t, results.Results[0], check.StatusAffected, "")
		wantAdvisory(t, results.Results[0], "CVE-2021-44228", check.VerdictAffected, "", "2.15.0")
		wantItem(t, results.Results[1], check.StatusAffected, "")
		wantAdvisory(t, results.Results[1], stepped, check.VerdictAffected, "", "2.5")
	})

	t.Run("Entry with no version information", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90107"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget", `{"version":"unspecified","status":"affected"}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "1.0", "2.0")))

		res := checkItems(t, f, cpeItem("acme:widget", "2.5")).Results[0]
		wantItem(t, res, check.StatusNotAffected, "")
		if res.Counts.NotAffected != 1 {
			t.Errorf("counts %+v, want the advisory not affected", res.Counts)
		}
	})

	t.Run("Mixed snapshot", func(t *testing.T) {
		t.Skip("covered by internal/store TestReadCheckCandidates_OneSnapshot, which commits a merge between two reads " +
			"of one snapshot; a request cannot place a commit between its own statements")
	})

	t.Run("Copies disagree", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90109"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1","lessThan":"2","status":"affected","versionType":"custom"}`)))
		relay := nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "1", "2"))
		relay.CNAAffected = cnaFromCVE5(t, cve, acmeCNA("widget", `{"version":"1","lessThan":"3","status":"affected","versionType":"custom"}`))
		ingestCheckPatch(t, f, "nvd", relay)

		res := checkItems(t, f, cpeItem("acme:widget", "2.5")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		wantAdvisory(t, res, cve, check.VerdictAffected, "", "3")
	})

	t.Run("Name the table lacks", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		// ".NET 9.0 runtime" is no exact name in the table; the microsoft:.net row's
		// prefix ".net " finds it. NVD has not analysed the CVE.
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2026-70007", cna70007))

		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.20")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		a := wantAdvisory(t, res, "CVE-2026-70007", check.VerdictAffected, "", "9.0.21")
		want := []CheckMatchedRange{{Evidence: "cna", Introduced: "9.0.0", Fixed: "9.0.21"}}
		if !slices.Equal(a.MatchedRanges, want) {
			t.Errorf("matched_ranges = %+v, want %+v", a.MatchedRanges, want)
		}
	})

	// nearbyNameFixture holds a CVE whose only CNA entry is an ASP.NET Core entry,
	// plus the given NVD rows.
	nearbyNameFixture := func(t *testing.T, cve string, nvd ...feed.CPEMatch) *securityFixture {
		t.Helper()
		f := newCompleteCheckFixture(t)
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, cnaASPNETCore))
		if len(nvd) > 0 {
			ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, nvd...))
		}
		return f
	}

	t.Run("Nearby name", func(t *testing.T) {
		t.Parallel()
		const cve = "CVE-2026-90111"
		f := nearbyNameFixture(t, cve)
		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.20")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "cna_name_uncertain", "")
	})

	t.Run("The .NET Framework is another product of .NET", func(t *testing.T) {
		t.Parallel()
		const cve = "CVE-2026-90116"
		f := newCompleteCheckFixture(t)
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, cna70007Framework48))
		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.20")).Results[0]
		wantNoAdvisory(t, res, cve)
		wantItem(t, res, check.StatusNoAdvisoryFound, "")
	})

	t.Run("An unrelated CPE does not count as analysis", func(t *testing.T) {
		t.Parallel()
		const cve = "CVE-2026-90112"
		f := nearbyNameFixture(t, cve, vulnerableCPE("a:nodejs:node.js", "24.0.0", "24.22.1"))
		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.20")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "cna_name_uncertain", "")
	})

	t.Run("The vendor's other CPE does", func(t *testing.T) {
		t.Parallel()
		const cve = "CVE-2026-90113"
		f := nearbyNameFixture(t, cve, vulnerableCPE("a:microsoft:asp.net_core", "9.0.0", "9.0.11"))
		res := checkItems(t, f, cpeItem("microsoft:.net", "9.0.20")).Results[0]
		wantNoAdvisory(t, res, cve)
		wantItem(t, res, check.StatusNoAdvisoryFound, "")
		if !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{})) {
			t.Errorf("counts %+v, want none: the CVE is not one of the item's advisories", res.Counts)
		}
	})

	t.Run("unknown first segment", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90114"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1.0","lessThan":"3.0","status":"unknown","changes":[{"at":"2.0","status":"affected"}]}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "5.0", "6.0")))

		results := checkItems(t, f, cpeItem("acme:widget", "1.5"), cpeItem("acme:widget", "2.5"))
		wantItem(t, results.Results[0], check.StatusUnresolved, "")
		wantAdvisory(t, results.Results[0], cve, check.VerdictCannotEvaluate, "cna_indeterminate", "")
		wantItem(t, results.Results[1], check.StatusAffected, "")
		wantAdvisory(t, results.Results[1], cve, check.VerdictAffected, "", "3.0")
	})

	t.Run("Unreadable lower bound", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90115"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1.0rc1","lessThan":"2.0","status":"affected","versionType":"custom"}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "5.0", "6.0")))

		res := checkItems(t, f, cpeItem("acme:widget", "1.5")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "cna_indeterminate", "")
	})

	t.Run("Unsorted changes[]", func(t *testing.T) {
		t.Parallel()
		// Table test: internal/check TestReadCNAEntry, "plan: changes given in
		// reverse order" cases. Here one product's entry lists the changes sorted
		// and another's in reverse, and every version answers the same for both.
		f := newCompleteCheckFixture(t)
		for cve, entry := range map[string]string{
			"CVE-2026-90116": acmeCNA("sorted", `{"version":"1.0","lessThan":"3.0","status":"unaffected","changes":[{"at":"2.0","status":"affected"},{"at":"2.5","status":"unaffected"}]}`),
			"CVE-2026-90117": acmeCNA("reversed", `{"version":"1.0","lessThan":"3.0","status":"unaffected","changes":[{"at":"2.5","status":"unaffected"},{"at":"2.0","status":"affected"}]}`),
		} {
			ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, entry))
		}
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch("CVE-2026-90116", vulnerableCPE("a:acme:sorted", "5.0", "6.0")))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch("CVE-2026-90117", vulnerableCPE("a:acme:reversed", "5.0", "6.0")))

		for _, v := range []string{"1.5", "2.2", "2.7"} {
			results := checkItems(t, f, cpeItem("acme:sorted", v), cpeItem("acme:reversed", v))
			sorted, reversed := results.Results[0], results.Results[1]
			if sorted.Status != reversed.Status || strOrEmpty(sorted.Reason) != strOrEmpty(reversed.Reason) ||
				!reflect.DeepEqual(sorted.Counts, reversed.Counts) || len(sorted.Advisories) != len(reversed.Advisories) {
				t.Errorf("%s: sorted %s %+v %s, reversed %s %+v %s", v, sorted.Status, sorted.Counts, describeAdvisories(sorted),
					reversed.Status, reversed.Counts, describeAdvisories(reversed))
				continue
			}
			for i := range sorted.Advisories {
				s, r := sorted.Advisories[i], reversed.Advisories[i]
				if s.Verdict != r.Verdict || strOrEmpty(s.Reason) != strOrEmpty(r.Reason) || strOrEmpty(s.FixedVersion) != strOrEmpty(r.FixedVersion) {
					t.Errorf("%s: sorted %s, reversed %s", v, describeAdvisories(sorted), describeAdvisories(reversed))
				}
			}
		}
		// The sorted reading itself (design section 4.3): first unaffected segment,
		// then affected, then above a later unaffected start.
		results := checkItems(t, f, cpeItem("acme:sorted", "1.5"), cpeItem("acme:sorted", "2.2"), cpeItem("acme:sorted", "2.7"))
		wantItem(t, results.Results[0], check.StatusNotAffected, "")
		wantAdvisory(t, results.Results[1], "CVE-2026-90116", check.VerdictAffected, "", "2.5")
		wantAdvisory(t, results.Results[2], "CVE-2026-90116", check.VerdictCannotEvaluate, "cna_indeterminate", "")
	})

	t.Run("Wildcard with a change", func(t *testing.T) {
		t.Parallel()
		// Table test: internal/check TestReadCNAEntry, cnaStarWithChange cases.
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90118"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1","lessThan":"*","status":"affected","changes":[{"at":"2","status":"unaffected"}]}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "5.0", "6.0")))

		results := checkItems(t, f, cpeItem("acme:widget", "1.5"), cpeItem("acme:widget", "2"), cpeItem("acme:widget", "2.5"))
		wantAdvisory(t, results.Results[0], cve, check.VerdictAffected, "", "2")
		// No statement at the start of the unaffected segment, so NVD's rows answer.
		wantItem(t, results.Results[1], check.StatusNotAffected, "")
		wantAdvisory(t, results.Results[2], cve, check.VerdictCannotEvaluate, "cna_indeterminate", "")
	})

	t.Run("Outer bounds unreadable, inner readable", func(t *testing.T) {
		t.Parallel()
		// Table test: internal/check TestReadCNAEntry, cnaLog4j44228 cases. The
		// golden CVE-2021-44228 entry has lower bound 2.0-beta9 and upper bound
		// log4j-core*, which dotted-number comparison cannot read.
		f := newCompleteCheckFixture(t)
		ingestCheckPatch(t, f, "mitre", testutil.GoldenPatch(t, "mitre", "CVE-2021-44228"))

		res := checkItems(t, f, cpeItem("apache_software_foundation:apache_log4j2", "2.14.0")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		a := wantAdvisory(t, res, "CVE-2021-44228", check.VerdictAffected, "", "2.15.0")
		want := []CheckMatchedRange{{Evidence: "cna", Introduced: "2.13.0", Fixed: "2.15.0"}}
		if !slices.Equal(a.MatchedRanges, want) {
			t.Errorf("matched_ranges = %+v, want %+v", a.MatchedRanges, want)
		}
	})

	t.Run("CNA purl with a registry", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const versions = `[{"version":"1.0.0","lessThan":"2.0.0","status":"affected","versionType":"semver"}]`
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2026-90119",
			`[{"packageURL":"pkg:npm/foo?repository_url=https://registry.example.com/","versions":`+versions+`}]`))
		// The same entry naming the public registry's package does match.
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2026-90120",
			`[{"packageURL":"pkg:npm/bar","versions":`+versions+`}]`))

		results := checkItems(t, f, pkgItem("npm", "foo", "1.5.0"), pkgItem("npm", "bar", "1.5.0"))
		wantItem(t, results.Results[0], check.StatusNoAdvisoryFound, "")
		wantNoAdvisory(t, results.Results[0], "CVE-2026-90119")
		wantItem(t, results.Results[1], check.StatusAffected, "")
		wantAdvisory(t, results.Results[1], "CVE-2026-90120", check.VerdictAffected, "", "2.0.0")
	})

	t.Run("PyPI separators", func(t *testing.T) {
		t.Parallel()
		// Table test: internal/ecosystem TestPackageKey, "pkg:pypi/friendly--bard".
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90121"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, `[{"packageURL":"pkg:pypi/friendly--bard","versions":[
			{"version":"1.0","lessThan":"2.0","status":"affected","versionType":"python"}]}]`))

		results := checkItems(t, f, pkgItem("PyPI", "friendly-bard", "1.5"), `{"purl":"pkg:pypi/friendly_bard@1.5"}`)
		for _, res := range results.Results {
			wantItem(t, res, check.StatusAffected, "")
			wantAdvisory(t, res, cve, check.VerdictAffected, "", "2.0")
		}
	})

	t.Run("Name longer than the index key", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		common := strings.Repeat("x", 256)
		const versions = `{"version":"1.0","lessThan":"2.0","status":"affected","versionType":"custom"}`
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2026-90122", acmeCNA(common+"exact", versions)))
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, "CVE-2026-90123", acmeCNA(common+"other", versions)))

		res := checkItems(t, f, cpeItem("acme:"+common+"exact", "1.5")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		wantAdvisory(t, res, "CVE-2026-90122", check.VerdictAffected, "", "2.0")
		wantNoAdvisory(t, res, "CVE-2026-90123")
		if !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{Affected: 1})) {
			t.Errorf("counts %+v, want only the exact name's advisory", res.Counts)
		}
	})

	t.Run("Range limit counts CNA entries", func(t *testing.T) {
		t.Parallel()
		// Table test: internal/check TestEvaluateTooManyRanges and TestCNARangeCount.
		// Here one stored CNA row holds 1,001 versions entries, past the default
		// limit of 1,000 ranges for one component in one advisory.
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90124"
		entries := make([]string, 0, check.DefaultLimits.AdvisoryRanges+1)
		for i := range check.DefaultLimits.AdvisoryRanges + 1 {
			entries = append(entries, fmt.Sprintf(`{"version":"%d.0","lessThan":"%d.1","status":"affected","versionType":"custom"}`, i+1, i+1))
		}
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget", strings.Join(entries, ","))))

		res := checkItems(t, f, cpeItem("acme:widget", "5.0")).Results[0]
		wantItem(t, res, check.StatusCannotEvaluate, "too_many_ranges")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "too_many_ranges", "")
	})

	t.Run("Private namespace", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		res := checkItems(t, f, `{"purl":"pkg:hex/acme/foo@2.3.0"}`).Results[0]
		if res.Status != check.StatusInvalid || res.Error == nil || res.Error.Code != "unsupported_purl_namespace" {
			t.Errorf("status %q, error %+v; want invalid with unsupported_purl_namespace", res.Status, res.Error)
		}
	})

	t.Run("Conflicting epochs", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		res := checkItems(t, f, `{"purl":"pkg:deb/debian/foo@2:1.0?distro=debian-13&epoch=1"}`).Results[0]
		if res.Status != check.StatusInvalid || res.Error == nil || res.Error.Code != "conflicting_version" {
			t.Errorf("status %q, error %+v; want invalid with conflicting_version", res.Status, res.Error)
		}
	})

	t.Run("Retracted, distro", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90125"
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: cve, SourceID: cve, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "Ubuntu:26.04:LTS", PackageName: "retracted-src", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0-2"}}})
		ingestCheckPatch(t, f, "mitre", rejectedByMITRE(cve))

		res := checkItems(t, f, pkgItem("Ubuntu:26.04:LTS", "retracted-src", "1.0-1")).Results[0]
		wantItem(t, res, check.StatusNoAdvisoryFound, "")
		if !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{Retracted: 1})) {
			t.Errorf("counts %+v, want one retracted", res.Counts)
		}
	})

	t.Run("Candidates a comparator cannot order", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90126"
		ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
			`{"version":"1.0","lessThan":"1.1rc1","status":"affected","versionType":"python"}`)))
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "1.0", "1.2")))

		res := checkItems(t, f, cpeItem("acme:widget", "1.0.5")).Results[0]
		wantItem(t, res, check.StatusAffected, "")
		a := wantAdvisory(t, res, cve, check.VerdictAffected, "", "")
		if a.MatchedRangesTotal != 2 {
			t.Errorf("matched_ranges = %+v, want the NVD and the CNA range", a.MatchedRanges)
		}
	})

	t.Run("GIT only", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		const cve = "CVE-2026-90127"
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: cve, SourceID: cve, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "PyPI", PackageName: "git-only", RangeType: "GIT",
				Introduced: "0a1b2c3d4e5f60718293a4b5c6d7e8f901234567", Fixed: "89abcdef0123456789abcdef0123456789abcdef"}}})

		res := checkItems(t, f, pkgItem("PyPI", "git-only", "1.0")).Results[0]
		wantItem(t, res, check.StatusUnresolved, "")
		wantAdvisory(t, res, cve, check.VerdictCannotEvaluate, "commit_ranges_only", "")
	})

	t.Run("Product with no CNA name", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		ingestCheckPatch(t, f, "nvd", nvdCPEPatch("CVE-2026-90128", vulnerableCPE("a:acme:gadget", "1.0", "2.0")))

		res := checkItems(t, f, cpeItem("acme:gadget", "2.5")).Results[0]
		wantItem(t, res, check.StatusCannotEvaluate, "cna_product_not_mapped")
		if !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{NotAffected: 1})) {
			t.Errorf("counts %+v, want the advisory not affected", res.Counts)
		}
	})

	t.Run("Item limit across sources", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		// Two CVEs, each with one NVD row and one CNA row for acme:widget: four
		// candidate rows, two from each source.
		for _, cve := range []string{"CVE-2026-90129", "CVE-2026-90130"} {
			ingestCheckPatch(t, f, "mitre", mitreCNAPatch(t, cve, acmeCNA("widget",
				`{"version":"1.0","lessThan":"2.0","status":"affected","versionType":"custom"}`)))
			ingestCheckPatch(t, f, "nvd", nvdCPEPatch(cve, vulnerableCPE("a:acme:widget", "1.0", "2.0")))
		}

		f.api.checkLimits = check.Limits{ItemRows: 4, AdvisoryRanges: check.DefaultLimits.AdvisoryRanges}
		wantItem(t, checkItems(t, f, cpeItem("acme:widget", "5.0")).Results[0], check.StatusNotAffected, "")

		f.api.checkLimits = check.Limits{ItemRows: 3, AdvisoryRanges: check.DefaultLimits.AdvisoryRanges}
		res := checkItems(t, f, cpeItem("acme:widget", "5.0")).Results[0]
		wantItem(t, res, check.StatusCannotEvaluate, "too_many_candidates")
		if len(res.Advisories) != 0 || !reflect.DeepEqual(countsOf(res.Counts), (CheckCounts{})) {
			t.Errorf("counts %+v, advisories %s; want none listed past the limit", res.Counts, describeAdvisories(res))
		}
	})

	t.Run("Distro depends only on OSV", func(t *testing.T) {
		t.Parallel()
		f := newSecurityFixture(t)
		setCheckCursors(t, f, "osv")
		const advisory = "UBUNTU-CVE-2026-90131"
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: advisory, SourceID: advisory, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "Ubuntu:26.04:LTS", PackageName: "osv-only", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0-2"}}})

		results := checkItems(t, f, pkgItem("Ubuntu:26.04:LTS", "osv-only", "1.0-2"))
		res := results.Results[0]
		wantItem(t, res, check.StatusNotAffected, "")
		if !res.DataComplete || !results.DataComplete {
			t.Errorf("data_complete = %v (response %v), want true with GHSA and NVD absent", res.DataComplete, results.DataComplete)
		}
		if len(results.Feeds) != 1 || results.Feeds[0].Name != "osv" || !results.Feeds[0].Complete {
			t.Errorf("feeds = %+v, want osv alone, complete", results.Feeds)
		}
	})

	t.Run("Ubuntu standard and Pro streams", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		// A universe package whose fix Ubuntu publishes only in Pro, and a main
		// package whose fix it publishes only in the standard stream.
		const proOnly, stdOnly = "UBUNTU-CVE-2026-90136", "USN-9001-1"
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: proOnly, SourceID: proOnly, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "Ubuntu:Pro:22.04:LTS", PackageName: "universe-pkg", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "1.0-1ubuntu0.1~esm1"}}})
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: stdOnly, SourceID: stdOnly, AffectedPackages: []feed.AffectedPackage{
			{Ecosystem: "Ubuntu:22.04:LTS", PackageName: "main-pkg", RangeType: "ECOSYSTEM", Introduced: "0", Fixed: "2.0-1ubuntu0.2"}}})

		results := checkItems(t, f, pkgItem("Ubuntu:22.04:LTS", "universe-pkg", "1.0-1"), pkgItem("Ubuntu:Pro:22.04:LTS", "main-pkg", "2.0-1ubuntu0.1"),
			pkgItem("Ubuntu:Pro:FIPS-updates:22.04:LTS", "main-pkg", "2.0-1ubuntu0.1"))
		wantItem(t, results.Results[0], check.StatusAffected, "")
		a := wantAdvisory(t, results.Results[0], proOnly, check.VerdictAffected, "", "1.0-1ubuntu0.1~esm1")
		if a != nil && (a.FixEcosystem == nil || *a.FixEcosystem != "Ubuntu:Pro:22.04:LTS") {
			t.Errorf("fix_ecosystem = %v, want Ubuntu:Pro:22.04:LTS", a.FixEcosystem)
		}
		wantItem(t, results.Results[1], check.StatusAffected, "")
		a = wantAdvisory(t, results.Results[1], stdOnly, check.VerdictAffected, "", "2.0-1ubuntu0.2")
		if a != nil && (len(a.MatchedRanges) != 1 || a.MatchedRanges[0].Ecosystem != "Ubuntu:22.04:LTS") {
			t.Errorf("matched_ranges = %+v, want one from Ubuntu:22.04:LTS", a.MatchedRanges)
		}
		// A sub-stream reads only its own rows, and has none here.
		wantItem(t, results.Results[2], check.StatusCannotEvaluate, "distro_stream_incomplete")
	})

	t.Run("Per-item limit", func(t *testing.T) {
		t.Parallel()
		f := newCompleteCheckFixture(t)
		for _, cve := range []string{"CVE-2026-90132", "CVE-2026-90133", "CVE-2026-90134"} {
			ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: cve, SourceID: cve, AffectedPackages: []feed.AffectedPackage{
				{Ecosystem: "npm", PackageName: "big-pkg", RangeType: "SEMVER", Introduced: "0", Fixed: "2.0.0"}}})
		}
		ingestCheckPatch(t, f, "osv", feed.CanonicalPatch{CVEID: "CVE-2026-90135", SourceID: "CVE-2026-90135",
			AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "small-pkg", RangeType: "SEMVER", Introduced: "0", Fixed: "2.0.0"}}})
		f.api.checkLimits = check.Limits{ItemRows: 2, AdvisoryRanges: check.DefaultLimits.AdvisoryRanges}

		results := checkItems(t, f, pkgItem("npm", "big-pkg", "1.0.0"), pkgItem("npm", "small-pkg", "1.0.0"))
		wantItem(t, results.Results[0], check.StatusCannotEvaluate, "too_many_candidates")
		if len(results.Results[0].Advisories) != 0 {
			t.Errorf("over the limit: advisories %s, want none", describeAdvisories(results.Results[0]))
		}
		wantItem(t, results.Results[1], check.StatusAffected, "")
		wantAdvisory(t, results.Results[1], "CVE-2026-90135", check.VerdictAffected, "", "2.0.0")
	})
}

// countsOf returns c without its counts by reason, so a test can compare the
// totals alone.
func countsOf(c CheckCounts) CheckCounts {
	c.CannotEvaluateByReason = nil
	return c
}
