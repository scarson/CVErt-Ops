// ABOUTME: Tests alert rules bound to a watchlist of CVE IDs through the real merge pipeline and evaluator.
// ABOUTME: The evaluator runs as cvert_ops_app, so its reads of org-scoped tables pass through RLS.
package alert_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/alert"
	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/feed/epss"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

const kevCondition = `[{"field":"in_cisa_kev","operator":"eq","value":true}]`

// cveListFixture is one org with a watchlist and an active rule bound to it, evaluated as
// the application role with a recording dispatcher.
type cveListFixture struct {
	tdb        *testutil.TestDB
	db         *sql.DB
	orgID      uuid.UUID
	watchlist  uuid.UUID
	rule       *store.AlertRuleRow
	evaluator  *alert.Evaluator
	dispatcher *mockDispatcher
}

func newCVEListFixture(t *testing.T, ctx context.Context, tdb *testutil.TestDB, conditions string) *cveListFixture {
	t.Helper()
	db := tdb.DB()
	orgID := createTestOrg(t, db)
	wl, err := tdb.CreateWatchlist(ctx, orgID, uuid.NullUUID{}, "scanner findings", sql.NullString{})
	if err != nil {
		t.Fatalf("CreateWatchlist: %v", err)
	}
	rule := mustRule(t, ctx, tdb.Store, orgID, "and", conditions, []uuid.UUID{wl.ID})
	activateRule(t, ctx, tdb.Store, orgID, rule.ID)

	dispatcher := &mockDispatcher{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	evaluator := alert.New(tdb.AppStore.DB(), tdb.AppStore, alert.NewRuleCache(), log, 0)
	evaluator.SetDispatcher(dispatcher)
	return &cveListFixture{
		tdb: tdb, db: db, orgID: orgID, watchlist: wl.ID, rule: rule,
		evaluator: evaluator, dispatcher: dispatcher,
	}
}

func (f *cveListFixture) push(t *testing.T, ctx context.Context, cveIDs ...string) store.ReplaceWatchlistItemsResult {
	t.Helper()
	items := make([]store.CreateWatchlistItemParams, 0, len(cveIDs))
	for _, id := range cveIDs {
		items = append(items, store.CreateWatchlistItemParams{ItemType: "cve", CveID: &id})
	}
	result, err := f.tdb.AppStore.ReplaceWatchlistItems(ctx, f.orgID, f.watchlist, items)
	if err != nil {
		t.Fatalf("ReplaceWatchlistItems: %v", err)
	}
	if result == nil {
		t.Fatal("ReplaceWatchlistItems: watchlist not found")
	}
	return *result
}

func (f *cveListFixture) evaluateBatch(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.evaluator.EvaluateBatch(ctx); err != nil {
		t.Fatalf("EvaluateBatch: %v", err)
	}
}

func (f *cveListFixture) fanouts(cveID string) int {
	f.dispatcher.mu.Lock()
	defer f.dispatcher.mu.Unlock()
	n := 0
	for _, call := range f.dispatcher.calls {
		if call.cveID == cveID && call.ruleID == f.rule.ID {
			n++
		}
	}
	return n
}

// ingestPublished runs a CVE through the merge pipeline as an NVD record.
func ingestPublished(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID, description string) {
	t.Helper()
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{
		CVEID:              cveID,
		Status:             "Published",
		DescriptionPrimary: &description,
	}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(nvd, %s): %v", cveID, err)
	}
}

// ingestSeverityChange runs a material change to a CVE through the merge pipeline.
func ingestSeverityChange(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID string) {
	t.Helper()
	severity := "HIGH"
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{CVEID: cveID, Severity: &severity}, "nvd"); err != nil {
		t.Fatalf("merge.Ingest(nvd, %s): %v", cveID, err)
	}
}

// ingestKEVListing runs a CVE through the merge pipeline as a CISA KEV record.
func ingestKEVListing(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID string) {
	t.Helper()
	inKEV := true
	if err := merge.Ingest(ctx, tdb.Store, feed.CanonicalPatch{CVEID: cveID, InCISAKEV: &inKEV}, "kev"); err != nil {
		t.Fatalf("merge.Ingest(kev, %s): %v", cveID, err)
	}
}

// applyEPSSScore runs one CVE's score through the real EPSS adapter.
func applyEPSSScore(t *testing.T, ctx context.Context, tdb *testutil.TestDB, cveID string, score float64) {
	t.Helper()
	var csv bytes.Buffer
	gz := gzip.NewWriter(&csv)
	fmt.Fprintf(gz, "#model_version:v2025.03.14,score_date:%s\ncve,epss,percentile\n%s,%f,0.5\n",
		time.Now().UTC().Format(time.RFC3339), cveID, score)
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip EPSS fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(csv.Bytes())
	}))
	defer srv.Close()
	client := &http.Client{
		Transport: testutil.NewURLRewriteTransport("https://epss.empiricalsecurity.com", srv.URL, http.DefaultTransport),
	}
	if _, err := epss.New(client).Apply(ctx, tdb.DB(), nil); err != nil {
		t.Fatalf("EPSS Apply: %v", err)
	}
}

// ageCorpus moves every CVE's change timestamps an hour back, outside the window each
// evaluator run re-scans behind its cursor.
func ageCorpus(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `
		UPDATE cves SET date_modified_canonical = now() - interval '1 hour',
		                date_epss_updated = now() - interval '1 hour'`); err != nil {
		t.Fatalf("age corpus: %v", err)
	}
}

func assertRuleStillActive(t *testing.T, ctx context.Context, f *cveListFixture) {
	t.Helper()
	if status := getRuleStatus(t, f.db, f.rule.ID); status != "active" {
		t.Errorf("rule status = %q, want active", status)
	}
	var jobs int
	if err := f.db.QueryRowContext(ctx,
		`SELECT count(*) FROM job_queue WHERE queue = 'alert_activation'`).Scan(&jobs); err != nil {
		t.Fatalf("count activation jobs: %v", err)
	}
	if jobs != 0 {
		t.Errorf("%d activation jobs enqueued, want 0", jobs)
	}
}

func TestWatchlistCVE_AlertsWhenListedCVEEntersKEV(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2026-10001"

	ingestPublished(t, ctx, tdb, cveID, "a flaw")
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.evaluateBatch(t, ctx)

	f.push(t, ctx, cveID)
	assertRuleStillActive(t, ctx, f)

	f.evaluateBatch(t, ctx)
	if n := countAllAlertEventsForRule(t, f.db, f.rule.ID); n != 0 {
		t.Fatalf("%d events before the CVE is in KEV, want 0", n)
	}

	ingestKEVListing(t, ctx, tdb, cveID)
	f.evaluateBatch(t, ctx)

	if n := countAlertEvents(t, f.db, f.rule.ID, cveID); n != 1 {
		t.Fatalf("%d events after the CVE entered KEV, want 1", n)
	}
	if getSuppressDelivery(t, f.db, f.rule.ID, cveID) {
		t.Error("event has suppress_delivery set, want a delivered alert")
	}
	if n := f.fanouts(cveID); n != 1 {
		t.Errorf("%d fan-outs, want 1", n)
	}

	f.evaluateBatch(t, ctx)
	if n := f.fanouts(cveID); n != 1 {
		t.Errorf("%d fan-outs after a repeat run, want 1", n)
	}
	assertRuleStillActive(t, ctx, f)
}

// TestWatchlistCVE_AlreadyInKEVAlertsAfterAdded covers a CVE that entered KEV long before it
// was listed. Nothing modifies the CVE, so the modified-date cursor alone never reaches it.
func TestWatchlistCVE_AlreadyInKEVAlertsAfterAdded(t *testing.T) {
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	testutil.SeedCorpus(t, tdb)

	var kevCVE, otherCVE string
	if err := tdb.DB().QueryRowContext(ctx,
		`SELECT cve_id FROM cves WHERE in_cisa_kev ORDER BY cve_id LIMIT 1`).Scan(&kevCVE); err != nil {
		t.Fatalf("find KEV CVE in corpus: %v", err)
	}
	if err := tdb.DB().QueryRowContext(ctx,
		`SELECT cve_id FROM cves WHERE NOT in_cisa_kev ORDER BY cve_id LIMIT 1`).Scan(&otherCVE); err != nil {
		t.Fatalf("find non-KEV CVE in corpus: %v", err)
	}

	ageCorpus(t, ctx, tdb.DB())
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.evaluateBatch(t, ctx)

	f.push(t, ctx, kevCVE, otherCVE)
	assertRuleStillActive(t, ctx, f)
	f.evaluateBatch(t, ctx)

	if n := countAlertEvents(t, f.db, f.rule.ID, kevCVE); n != 1 {
		t.Fatalf("%d events for %s (in KEV before it was listed), want 1", n, kevCVE)
	}
	if getSuppressDelivery(t, f.db, f.rule.ID, kevCVE) {
		t.Error("event has suppress_delivery set, want a delivered alert")
	}
	if n := f.fanouts(kevCVE); n != 1 {
		t.Errorf("%d fan-outs for %s, want 1", n, kevCVE)
	}
	if n := countAlertEvents(t, f.db, f.rule.ID, otherCVE); n != 0 {
		t.Errorf("%d events for %s (not in KEV), want 0", n, otherCVE)
	}

	// The add stays inside the re-scan window for the next run, and the push repeats.
	f.evaluateBatch(t, ctx)
	if got, want := f.push(t, ctx, kevCVE, otherCVE), (store.ReplaceWatchlistItemsResult{Unchanged: 2}); got != want {
		t.Errorf("repeat push = %+v, want %+v", got, want)
	}
	f.evaluateBatch(t, ctx)
	if n := f.fanouts(kevCVE); n != 1 {
		t.Errorf("%d fan-outs after repeat runs, want 1", n)
	}
	assertRuleStillActive(t, ctx, f)
}

func TestWatchlistCVE_RemovedCVEStopsMatching(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const removed, kept = "CVE-2026-10002", "CVE-2026-10003"

	for _, id := range []string{removed, kept} {
		ingestPublished(t, ctx, tdb, id, "a flaw")
		ingestKEVListing(t, ctx, tdb, id)
	}
	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.push(t, ctx, removed, kept)
	f.evaluateBatch(t, ctx)
	if n := f.fanouts(removed); n != 1 {
		t.Fatalf("%d fan-outs for %s before removal, want 1", n, removed)
	}

	if got, want := f.push(t, ctx, kept), (store.ReplaceWatchlistItemsResult{Removed: 1, Unchanged: 1}); got != want {
		t.Fatalf("smaller push = %+v, want %+v", got, want)
	}
	ageCorpus(t, ctx, tdb.DB())
	f.evaluateBatch(t, ctx)

	if getMatchState(t, f.db, f.rule.ID, removed) {
		t.Errorf("%s still in matched state after removal", removed)
	}
	if !getMatchState(t, f.db, f.rule.ID, kept) {
		t.Errorf("%s left matched state but is still listed", kept)
	}

	// A material change to the removed CVE no longer alerts.
	ingestSeverityChange(t, ctx, tdb, removed)
	f.evaluateBatch(t, ctx)
	if n := countAlertEvents(t, f.db, f.rule.ID, removed); n != 1 {
		t.Errorf("%d events for removed CVE after a material change, want 1", n)
	}
	if n := f.fanouts(removed); n != 1 {
		t.Errorf("%d fan-outs for removed CVE after a material change, want 1", n)
	}

	// The same change to the listed CVE still alerts.
	ingestSeverityChange(t, ctx, tdb, kept)
	f.evaluateBatch(t, ctx)
	if n := f.fanouts(kept); n != 2 {
		t.Errorf("%d fan-outs for listed CVE after a material change, want 2", n)
	}
}

func TestWatchlistCVE_ListedBeforeFeedDeliversIt(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2026-10004"

	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	f.push(t, ctx, cveID)
	f.evaluateBatch(t, ctx)
	if n := countAllAlertEventsForRule(t, f.db, f.rule.ID); n != 0 {
		t.Fatalf("%d events for a CVE not in the corpus, want 0", n)
	}

	ingestPublished(t, ctx, tdb, cveID, "a flaw")
	ingestKEVListing(t, ctx, tdb, cveID)
	f.evaluateBatch(t, ctx)
	if n := f.fanouts(cveID); n != 1 {
		t.Errorf("%d fan-outs once the feed delivered the CVE, want 1", n)
	}
}

// TestWatchlistCVE_EPSSOnlyRule covers both ways an EPSS-only rule reaches a listed CVE:
// its score rises past the threshold, or it is listed with a score already past it.
func TestWatchlistCVE_EPSSOnlyRule(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const rises, alreadyHigh = "CVE-2026-10005", "CVE-2026-10006"

	ingestPublished(t, ctx, tdb, rises, "a flaw")
	ingestPublished(t, ctx, tdb, alreadyHigh, "another flaw")
	applyEPSSScore(t, ctx, tdb, rises, 0.1)
	applyEPSSScore(t, ctx, tdb, alreadyHigh, 0.9)

	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	conditions := json.RawMessage(`[{"field":"epss_score","operator":"gt","value":0.5}]`)
	rule, err := tdb.CreateAlertRule(ctx, f.orgID, store.CreateAlertRuleParams{
		Name:             "epss jump",
		Logic:            "and",
		Conditions:       conditions,
		WatchlistIds:     []uuid.UUID{f.watchlist},
		HasEpssCondition: true,
		IsEpssOnly:       true,
		Status:           "draft",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	activateRule(t, ctx, tdb.Store, f.orgID, rule.ID)
	f.rule = rule

	evaluateEPSS := func() {
		t.Helper()
		if err := f.evaluator.EvaluateEPSS(ctx); err != nil {
			t.Fatalf("EvaluateEPSS: %v", err)
		}
	}
	ageCorpus(t, ctx, tdb.DB())
	evaluateEPSS()

	f.push(t, ctx, rises)
	evaluateEPSS()
	if n := f.fanouts(rises); n != 0 {
		t.Fatalf("%d fan-outs below the threshold, want 0", n)
	}

	applyEPSSScore(t, ctx, tdb, rises, 0.8)
	evaluateEPSS()
	if n := f.fanouts(rises); n != 1 {
		t.Errorf("%d fan-outs after the score rose, want 1", n)
	}

	f.push(t, ctx, rises, alreadyHigh)
	evaluateEPSS()
	if n := f.fanouts(alreadyHigh); n != 1 {
		t.Errorf("%d fan-outs for a CVE listed with a high score, want 1", n)
	}
}

// TestWatchlistCVE_PushDoesNotReachOtherOrgs checks that a list change only causes
// evaluation of rules bound to that list.
func TestWatchlistCVE_PushDoesNotReachOtherOrgs(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const cveID = "CVE-2026-10007"

	ingestPublished(t, ctx, tdb, cveID, "a flaw")
	ingestKEVListing(t, ctx, tdb, cveID)
	ageCorpus(t, ctx, tdb.DB())

	pusher := newCVEListFixture(t, ctx, tdb, kevCondition)
	bystander := newCVEListFixture(t, ctx, tdb, kevCondition)
	pusher.evaluateBatch(t, ctx)
	runsBefore := countRuns(t, tdb.DB(), bystander.rule.ID)

	pusher.push(t, ctx, cveID)
	pusher.evaluateBatch(t, ctx)

	if n := pusher.fanouts(cveID); n != 1 {
		t.Errorf("%d fan-outs for the org that listed the CVE, want 1", n)
	}
	if n := countAllAlertEventsForRule(t, tdb.DB(), bystander.rule.ID); n != 0 {
		t.Errorf("%d events for another org's rule, want 0", n)
	}
	if runs := countRuns(t, tdb.DB(), bystander.rule.ID); runs != runsBefore {
		t.Errorf("another org's rule ran %d times because of the push, want 0", runs-runsBefore)
	}
}

// TestWatchlistFilter_PackageAndCPEItemsStillMatch covers the item types that share the
// watchlist filter with CVE items: the package match ignores case and the CPE match is a
// prefix match.
func TestWatchlistFilter_PackageAndCPEItemsStillMatch(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)
	ctx := context.Background()
	const byPackage, byCPE, unrelated = "CVE-2026-10010", "CVE-2026-10011", "CVE-2026-10012"

	inKEV := true
	for _, patch := range []feed.CanonicalPatch{
		{CVEID: byPackage, InCISAKEV: &inKEV, AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "Lodash"}}},
		{CVEID: byCPE, InCISAKEV: &inKEV, AffectedCPEs: []feed.AffectedCPE{{
			CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", CPENormalized: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
		}}},
		{CVEID: unrelated, InCISAKEV: &inKEV, AffectedPackages: []feed.AffectedPackage{{Ecosystem: "pypi", PackageName: "lodash"}}},
	} {
		if err := merge.Ingest(ctx, tdb.Store, patch, "nvd"); err != nil {
			t.Fatalf("merge.Ingest(%s): %v", patch.CVEID, err)
		}
	}

	f := newCVEListFixture(t, ctx, tdb, kevCondition)
	eco, name, cpe := "npm", "lodash", "cpe:2.3:a:apache:log4j"
	if _, err := tdb.AppStore.ReplaceWatchlistItems(ctx, f.orgID, f.watchlist, []store.CreateWatchlistItemParams{
		{ItemType: "package", Ecosystem: &eco, PackageName: &name},
		{ItemType: "cpe", CpeNormalized: &cpe},
	}); err != nil {
		t.Fatalf("ReplaceWatchlistItems: %v", err)
	}
	f.evaluateBatch(t, ctx)

	if n := countAlertEvents(t, f.db, f.rule.ID, byPackage); n != 1 {
		t.Errorf("%d events for the package match, want 1", n)
	}
	if n := countAlertEvents(t, f.db, f.rule.ID, byCPE); n != 1 {
		t.Errorf("%d events for the CPE prefix match, want 1", n)
	}
	if n := countAlertEvents(t, f.db, f.rule.ID, unrelated); n != 0 {
		t.Errorf("%d events for a package in another ecosystem, want 0", n)
	}
}
