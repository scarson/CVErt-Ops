// ABOUTME: Tests how alert rules and watchlist package items match stored ecosystem values.
// ABOUTME: A base name covers every suffixed release of that ecosystem, through the real merge pipeline and evaluator.
package alert_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const (
	cveDebian13 = "CVE-2026-20001"
	cveDebian12 = "CVE-2026-20002"
	cveUbuntu   = "CVE-2026-20003"
	cveRedHat   = "CVE-2026-20004"
	cveLightw   = "CVE-2026-20005"
	cvePyPI     = "CVE-2026-20006"
	cveNpm      = "CVE-2026-20007"
)

var ecosystemMatchCorpus = []struct{ cveID, ecosystem, packageName string }{
	{cveDebian13, "Debian:13", "openssl"},
	{cveDebian12, "Debian:12", "openssl"},
	{cveUbuntu, "Ubuntu:24.04:LTS", "openssl"},
	{cveRedHat, "Red Hat:8", "openssl"},
	{cveLightw, "Red Hat Lightwell:1", "openssl"},
	{cvePyPI, "PyPI", "foo_bar"},
	{cveNpm, "npm", "foo_bar"},
}

func ingestEcosystemMatchCorpus(t *testing.T, ctx context.Context, tdb *testutil.TestDB) {
	t.Helper()
	inKEV := true
	for _, row := range ecosystemMatchCorpus {
		patch := feed.CanonicalPatch{
			CVEID:            row.cveID,
			InCISAKEV:        &inKEV,
			AffectedPackages: []feed.AffectedPackage{{Ecosystem: row.ecosystem, PackageName: row.packageName}},
		}
		if err := merge.Ingest(ctx, tdb.Store, patch, "nvd"); err != nil {
			t.Fatalf("merge.Ingest(%s): %v", row.cveID, err)
		}
	}
}

func (f *cveListFixture) setPackageItems(t *testing.T, ctx context.Context, items ...[2]string) {
	t.Helper()
	params := make([]store.CreateWatchlistItemParams, 0, len(items))
	for _, item := range items {
		eco, name := item[0], item[1]
		params = append(params, store.CreateWatchlistItemParams{ItemType: "package", Ecosystem: &eco, PackageName: &name})
	}
	if _, err := f.tdb.AppStore.ReplaceWatchlistItems(ctx, f.orgID, f.watchlist, params); err != nil {
		t.Fatalf("ReplaceWatchlistItems: %v", err)
	}
}

// assertEventsOnly checks every CVE in the corpus: one event for each listed CVE, none for the rest.
func (f *cveListFixture) assertEventsOnly(t *testing.T, want ...string) {
	t.Helper()
	for _, row := range ecosystemMatchCorpus {
		wantEvents := 0
		if slices.Contains(want, row.cveID) {
			wantEvents = 1
		}
		if n := countAlertEvents(t, f.db, f.rule.ID, row.cveID); n != wantEvents {
			t.Errorf("%d events on %s (%s %s), want %d", n, row.cveID, row.ecosystem, row.packageName, wantEvents)
		}
	}
}

func TestEcosystemMatch_WatchlistPackageItems(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	ingestEcosystemMatchCorpus(t, ctx, tdb)

	tests := []struct {
		name               string
		ecosystem, pkgName string
		want               []string
	}{
		{"base name covers every release", "Debian", "openssl", []string{cveDebian13, cveDebian12}},
		{"release matches only itself", "Debian:13", "openssl", []string{cveDebian13}},
		{"base name stops at the colon", "Red Hat", "openssl", []string{cveRedHat}},
		{"PyPI names compare with separators folded", "PyPI", "foo-bar", []string{cvePyPI}},
		{"other ecosystems keep separators distinct", "npm", "foo-bar", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newCVEListFixture(t, ctx, tdb, kevCondition)
			f.setPackageItems(t, ctx, [2]string{tt.ecosystem, tt.pkgName})
			f.evaluateBatch(t, ctx)
			f.assertEventsOnly(t, tt.want...)
		})
	}
}

func TestEcosystemMatch_RuleConditions(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	ingestEcosystemMatchCorpus(t, ctx, tdb)

	tests := []struct {
		name, operator, value string
		want                  []string
	}{
		{"eq base name", "eq", `"Debian"`, []string{cveDebian13, cveDebian12}},
		{"eq release", "eq", `"Debian:13"`, []string{cveDebian13}},
		{"in release and base name", "in", `["Debian:13","Ubuntu"]`, []string{cveDebian13, cveUbuntu}},
		{"neq base name", "neq", `"Debian"`, []string{cveUbuntu, cveRedHat, cveLightw}},
		{"not_in base names", "not_in", `["Debian","Red Hat"]`, []string{cveUbuntu, cveLightw}},
		{"eq stops at the colon", "eq", `"Red Hat"`, []string{cveRedHat}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conditions := fmt.Sprintf(`[{"field":"in_cisa_kev","operator":"eq","value":true},`+
				`{"field":"affected.ecosystem","operator":%q,"value":%s}]`, tt.operator, tt.value)
			f := newCVEListFixture(t, ctx, tdb, conditions)
			f.setPackageItems(t, ctx,
				[2]string{"Debian", "openssl"}, [2]string{"Ubuntu", "openssl"},
				[2]string{"Red Hat", "openssl"}, [2]string{"Red Hat Lightwell", "openssl"})
			f.evaluateBatch(t, ctx)
			f.assertEventsOnly(t, tt.want...)
		})
	}
}
