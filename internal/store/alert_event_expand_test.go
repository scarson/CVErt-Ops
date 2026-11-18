// ABOUTME: Integration tests for ListAlertEvents with CVE and rule context expanded in the same query.
// ABOUTME: Covers CVE fields, rule name, the watchlist items that match the event's CVE, and tenant isolation.
package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/feed"
	"github.com/scarson/cvert-ops/internal/merge"
	"github.com/scarson/cvert-ops/internal/store"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func ptr[T any](v T) *T { return &v }

// expandFixture is one org with a watchlist of three items (a CVE, a package and a
// CPE), a rule bound to it, and events for three CVEs held in the corpus and one that is not.
type expandFixture struct {
	org                        uuid.UUID
	rule                       uuid.UUID
	watchlist                  uuid.UUID
	cveItem, pkgItem, cpeItem  uuid.UUID
	pkgCVE, cpeCVE, plainCVE   string
	missingCVE, watchedCVEItem string
}

func newExpandFixture(t *testing.T, s *testutil.TestDB, orgName string) expandFixture {
	t.Helper()
	ctx := context.Background()
	f := expandFixture{
		pkgCVE:     "CVE-2024-71001",
		cpeCVE:     "CVE-2024-71002",
		plainCVE:   "CVE-2024-71003",
		missingCVE: "CVE-2024-71999",
	}
	f.watchedCVEItem = f.plainCVE
	f.org = s.MustCreateOrg(t, ctx, orgName).ID

	patches := []feed.CanonicalPatch{
		{
			CVEID: f.pkgCVE, Status: "published",
			Severity: ptr("HIGH"), CVSSv3Score: ptr(8.1), InCISAKEV: ptr(true),
			AffectedPackages: []feed.AffectedPackage{{Ecosystem: "npm", PackageName: "Lodash", Introduced: "0", Fixed: "4.17.21"}},
		},
		{
			CVEID: f.cpeCVE, Status: "published", Severity: ptr("critical"), CVSSv3Score: ptr(9.8),
			AffectedCPEs: []feed.AffectedCPE{{CPE: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", CPENormalized: "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"}},
		},
		{CVEID: f.plainCVE, Status: "published", Severity: ptr("LOW"), CVSSv3Score: ptr(3.1)},
	}
	for _, p := range patches {
		if err := merge.Ingest(ctx, s.Store, p, "nvd"); err != nil {
			t.Fatalf("ingest %s: %v", p.CVEID, err)
		}
	}
	// EPSS is not a merged field; it is written by the EPSS job.
	if _, err := s.DB().ExecContext(ctx, `UPDATE cves SET epss_score = 0.42 WHERE cve_id = $1`, f.pkgCVE); err != nil {
		t.Fatalf("set epss: %v", err)
	}

	wl, err := s.CreateWatchlist(ctx, f.org, uuid.NullUUID{}, "stack", sql.NullString{})
	if err != nil {
		t.Fatalf("create watchlist: %v", err)
	}
	f.watchlist = wl.ID
	addItem := func(p store.CreateWatchlistItemParams) uuid.UUID {
		item, err := s.CreateWatchlistItem(ctx, f.org, wl.ID, p)
		if err != nil {
			t.Fatalf("create watchlist item: %v", err)
		}
		return item.ID
	}
	f.cveItem = addItem(store.CreateWatchlistItemParams{ItemType: generated.WatchlistItemTypeCve, CveID: &f.watchedCVEItem})
	f.pkgItem = addItem(store.CreateWatchlistItemParams{ItemType: generated.WatchlistItemTypePackage, Ecosystem: ptr("npm"), PackageName: ptr("lodash")})
	f.cpeItem = addItem(store.CreateWatchlistItemParams{ItemType: generated.WatchlistItemTypeCpe, CpeNormalized: ptr("cpe:2.3:a:acme:widget")})
	// A deleted item that would match is left out.
	deleted := addItem(store.CreateWatchlistItemParams{ItemType: generated.WatchlistItemTypePackage, Ecosystem: ptr("npm"), PackageName: ptr("LODASH")})
	if ok, err := s.DeleteWatchlistItem(ctx, f.org, wl.ID, deleted); err != nil || !ok {
		t.Fatalf("delete watchlist item: deleted=%v, err=%v", ok, err)
	}

	rule, err := s.CreateAlertRule(ctx, f.org, store.CreateAlertRuleParams{
		Name:         "Stack watch",
		Logic:        "and",
		Conditions:   json.RawMessage(`[{"field":"cvss_v3_score","operator":"gte","value":0}]`),
		WatchlistIds: []uuid.UUID{wl.ID},
		Status:       "active",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	f.rule = rule.ID
	for _, cve := range []string{f.pkgCVE, f.cpeCVE, f.plainCVE, f.missingCVE} {
		if _, err := s.InsertAlertEvent(ctx, f.org, rule.ID, cve, "hash-"+cve, false); err != nil {
			t.Fatalf("insert event %s: %v", cve, err)
		}
	}
	return f
}

// byCVE indexes rows by CVE ID.
func byCVE(t *testing.T, rows []store.AlertEventListRow) map[string]store.AlertEventListRow {
	t.Helper()
	m := make(map[string]store.AlertEventListRow, len(rows))
	for _, r := range rows {
		m[r.CveID] = r
	}
	return m
}

func TestListAlertEvents_ExpandCVEAndRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	f := newExpandFixture(t, s, "ExpandOrg")

	// AppStore runs as the application role, so RLS applies to every joined table.
	rows, err := s.AppStore.ListAlertEvents(ctx, f.org, store.ListAlertEventsParams{Limit: 10, ExpandCVE: true, ExpandRule: true})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	got := byCVE(t, rows)
	if len(got) != 4 {
		t.Fatalf("got %d events, want 4", len(rows))
	}

	pkg := got[f.pkgCVE]
	if pkg.CVE == nil {
		t.Fatalf("%s: cve not expanded", f.pkgCVE)
	}
	if pkg.CVE.Severity == nil || *pkg.CVE.Severity != "HIGH" || !pkg.CVE.InCISAKEV ||
		pkg.CVE.CVSSv3Score == nil || *pkg.CVE.CVSSv3Score != 8.1 ||
		pkg.CVE.EPSSScore == nil || *pkg.CVE.EPSSScore != 0.42 {
		t.Errorf("%s cve = %+v, want HIGH, KEV, 8.1, EPSS 0.42", f.pkgCVE, *pkg.CVE)
	}
	if pkg.Rule == nil || pkg.Rule.Name != "Stack watch" || pkg.Rule.Deleted {
		t.Fatalf("%s rule = %+v, want Stack watch, not deleted", f.pkgCVE, pkg.Rule)
	}
	if len(pkg.Rule.WatchlistMatches) != 1 || pkg.Rule.WatchlistMatches[0].ItemID != f.pkgItem ||
		pkg.Rule.WatchlistMatches[0].ItemType != "package" || pkg.Rule.WatchlistMatches[0].WatchlistID != f.watchlist ||
		pkg.Rule.WatchlistMatches[0].PackageName == nil || *pkg.Rule.WatchlistMatches[0].PackageName != "lodash" {
		t.Errorf("%s matches = %+v, want only the lodash package item", f.pkgCVE, pkg.Rule.WatchlistMatches)
	}

	cpe := got[f.cpeCVE]
	if cpe.CVE == nil || cpe.CVE.EPSSScore != nil || cpe.CVE.InCISAKEV {
		t.Errorf("%s cve = %+v, want no EPSS, not KEV", f.cpeCVE, cpe.CVE)
	}
	if cpe.Rule == nil || len(cpe.Rule.WatchlistMatches) != 1 || cpe.Rule.WatchlistMatches[0].ItemID != f.cpeItem ||
		cpe.Rule.WatchlistMatches[0].CPE == nil || *cpe.Rule.WatchlistMatches[0].CPE != "cpe:2.3:a:acme:widget" {
		t.Errorf("%s rule = %+v, want only the CPE item", f.cpeCVE, cpe.Rule)
	}

	plain := got[f.plainCVE]
	if plain.Rule == nil || len(plain.Rule.WatchlistMatches) != 1 || plain.Rule.WatchlistMatches[0].ItemID != f.cveItem ||
		plain.Rule.WatchlistMatches[0].CveID == nil || *plain.Rule.WatchlistMatches[0].CveID != f.plainCVE {
		t.Errorf("%s rule = %+v, want only the CVE item", f.plainCVE, plain.Rule)
	}

	missing := got[f.missingCVE]
	if missing.CVE != nil {
		t.Errorf("%s cve = %+v, want nil for a CVE not in the corpus", f.missingCVE, *missing.CVE)
	}
	if missing.Rule == nil || len(missing.Rule.WatchlistMatches) != 0 {
		t.Errorf("%s rule = %+v, want the rule with no matches", f.missingCVE, missing.Rule)
	}
}

func TestListAlertEvents_NoExpandLeavesContextNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	f := newExpandFixture(t, s, "NoExpandOrg")

	rows, err := s.AppStore.ListAlertEvents(ctx, f.org, store.ListAlertEventsParams{Limit: 10, ExpandCVE: true})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	for _, r := range rows {
		if r.Rule != nil {
			t.Errorf("%s: rule expanded without ExpandRule", r.CveID)
		}
	}
	rows, err = s.AppStore.ListAlertEvents(ctx, f.org, store.ListAlertEventsParams{Limit: 10, ExpandRule: true})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	for _, r := range rows {
		if r.CVE != nil {
			t.Errorf("%s: cve expanded without ExpandCVE", r.CveID)
		}
	}
}

// TestListAlertEvents_ExpandRuleDeletedRule reports a soft-deleted rule by name, marked deleted.
func TestListAlertEvents_ExpandRuleDeletedRule(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	f := newExpandFixture(t, s, "DeletedRuleOrg")
	if err := s.SoftDeleteAlertRule(ctx, f.org, f.rule); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	rows, err := s.AppStore.ListAlertEvents(ctx, f.org, store.ListAlertEventsParams{Limit: 10, ExpandRule: true})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	for _, r := range rows {
		if r.Rule == nil || r.Rule.Name != "Stack watch" || !r.Rule.Deleted {
			t.Errorf("%s rule = %+v, want Stack watch marked deleted", r.CveID, r.Rule)
		}
	}
}

// TestListAlertEvents_ExpandRuleIsolation checks the expansion reads only the caller's
// org: another org's watchlist, holding items that match the same CVEs, adds no matches.
func TestListAlertEvents_ExpandRuleIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	f := newExpandFixture(t, s, "IsoOrgA")

	other := s.MustCreateOrg(t, ctx, "IsoOrgB")
	wl, err := s.CreateWatchlist(ctx, other.ID, uuid.NullUUID{}, "theirs", sql.NullString{})
	if err != nil {
		t.Fatalf("create watchlist: %v", err)
	}
	if _, err := s.CreateWatchlistItem(ctx, other.ID, wl.ID, store.CreateWatchlistItemParams{
		ItemType: generated.WatchlistItemTypePackage, Ecosystem: ptr("npm"), PackageName: ptr("lodash"),
	}); err != nil {
		t.Fatalf("create item: %v", err)
	}
	// Point the org's rule at the other org's watchlist too: its items must still not appear.
	if _, err := s.DB().ExecContext(ctx,
		`UPDATE alert_rules SET watchlist_ids = array_append(watchlist_ids, $1) WHERE id = $2`, wl.ID, f.rule); err != nil {
		t.Fatalf("bind foreign watchlist: %v", err)
	}

	rows, err := s.AppStore.ListAlertEvents(ctx, f.org, store.ListAlertEventsParams{Limit: 10, ExpandRule: true})
	if err != nil {
		t.Fatalf("ListAlertEvents: %v", err)
	}
	pkg := byCVE(t, rows)[f.pkgCVE]
	if pkg.Rule == nil || len(pkg.Rule.WatchlistMatches) != 1 || pkg.Rule.WatchlistMatches[0].ItemID != f.pkgItem {
		t.Errorf("matches = %+v, want only the org's own lodash item", pkg.Rule)
	}
	// The other org sees none of this org's events.
	theirs, err := s.AppStore.ListAlertEvents(ctx, other.ID, store.ListAlertEventsParams{Limit: 10, ExpandCVE: true, ExpandRule: true})
	if err != nil {
		t.Fatalf("ListAlertEvents(other): %v", err)
	}
	if len(theirs) != 0 {
		t.Errorf("other org got %d events, want 0", len(theirs))
	}
}
