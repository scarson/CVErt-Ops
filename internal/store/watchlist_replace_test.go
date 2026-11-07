// ABOUTME: Integration tests for CVE watchlist items and replacing a watchlist's whole item list.
// ABOUTME: Tenant isolation runs as cvert_ops_app with RLS in force, not as the superuser store.
package store_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func cveItem(id string) store.CreateWatchlistItemParams {
	return store.CreateWatchlistItemParams{ItemType: "cve", CveID: strPtr(id)}
}

func cveItems(ids ...string) []store.CreateWatchlistItemParams {
	items := make([]store.CreateWatchlistItemParams, 0, len(ids))
	for _, id := range ids {
		items = append(items, cveItem(id))
	}
	return items
}

// liveCVEIDs returns the sorted cve_id of every live cve item in the watchlist, keyed
// to the row id so a test can tell an untouched row from a re-created one.
func liveCVEIDs(t *testing.T, s *store.Store, ctx context.Context, orgID, watchlistID uuid.UUID) map[string]uuid.UUID {
	t.Helper()
	items, err := s.ListWatchlistItems(ctx, orgID, watchlistID, nil, nil, 1000)
	if err != nil {
		t.Fatalf("ListWatchlistItems: %v", err)
	}
	ids := make(map[string]uuid.UUID, len(items))
	for _, item := range items {
		if item.ItemType == "cve" {
			ids[item.CveID.String] = item.ID
		}
	}
	return ids
}

func mustReplace(t *testing.T, s *store.Store, ctx context.Context, orgID, watchlistID uuid.UUID, items []store.CreateWatchlistItemParams) store.ReplaceWatchlistItemsResult {
	t.Helper()
	result, err := s.ReplaceWatchlistItems(ctx, orgID, watchlistID, items)
	if err != nil {
		t.Fatalf("ReplaceWatchlistItems: %v", err)
	}
	if result == nil {
		t.Fatal("ReplaceWatchlistItems: watchlist not found")
	}
	return *result
}

func TestCreateWatchlistItem_CVE(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLCVE1")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	item, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, cveItem("CVE-2024-3094"))
	if err != nil {
		t.Fatalf("CreateWatchlistItem: %v", err)
	}
	if item.ItemType != "cve" || item.CveID.String != "CVE-2024-3094" {
		t.Errorf("item = (%q, %q), want (cve, CVE-2024-3094)", item.ItemType, item.CveID.String)
	}

	cveType := store.WatchlistItemType("cve")
	listed, err := s.ListWatchlistItems(ctx, org.ID, w.ID, &cveType, nil, 10)
	if err != nil {
		t.Fatalf("ListWatchlistItems: %v", err)
	}
	if len(listed) != 1 || listed[0].CveID.String != "CVE-2024-3094" {
		t.Errorf("listed = %+v, want one item naming CVE-2024-3094", listed)
	}
}

func TestCreateWatchlistItem_CVERequiresCVEID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLCVE2")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	_, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{ItemType: "cve"})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "wi_cve_fields" {
		t.Fatalf("err = %v, want violation of wi_cve_fields", err)
	}
}

func TestCreateWatchlistItem_CVEUniqueAmongLiveItems(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLCVE3")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	first, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, cveItem("CVE-2024-3094"))
	if err != nil {
		t.Fatalf("first CreateWatchlistItem: %v", err)
	}
	if _, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, cveItem("CVE-2024-3094")); err == nil {
		t.Fatal("second live item for the same CVE: want unique violation, got nil")
	}
	if _, err := s.DeleteWatchlistItem(ctx, org.ID, w.ID, first.ID); err != nil {
		t.Fatalf("DeleteWatchlistItem: %v", err)
	}
	if _, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, cveItem("CVE-2024-3094")); err != nil {
		t.Fatalf("re-add after soft delete: %v", err)
	}
}

func TestReplaceWatchlistItems_AddsToEmptyList(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace1")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001", "CVE-2024-0002"))

	if want := (store.ReplaceWatchlistItemsResult{Added: 2}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
	if live := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID); len(live) != 2 {
		t.Errorf("live items = %v, want 2", live)
	}
}

func TestReplaceWatchlistItems_SameListChangesNothing(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace2")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")
	items := cveItems("CVE-2024-0001", "CVE-2024-0002")

	mustReplace(t, s.Store, ctx, org.ID, w.ID, items)
	before := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)

	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, items)

	if want := (store.ReplaceWatchlistItemsResult{Unchanged: 2}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
	after := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)
	for id, rowID := range before {
		if after[id] != rowID {
			t.Errorf("%s row id changed from %s to %s", id, rowID, after[id])
		}
	}
	var total int
	if err := s.DB().QueryRowContext(ctx,
		`SELECT count(*) FROM watchlist_items WHERE watchlist_id = $1`, w.ID).Scan(&total); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if total != 2 {
		t.Errorf("rows including soft-deleted = %d, want 2 (no churn)", total)
	}
}

func TestReplaceWatchlistItems_SmallerListRemovesDropped(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace3")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"))
	before := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)

	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0002", "CVE-2024-0004"))

	if want := (store.ReplaceWatchlistItemsResult{Added: 1, Removed: 2, Unchanged: 1}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
	after := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)
	ids := make([]string, 0, len(after))
	for id := range after {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"CVE-2024-0002", "CVE-2024-0004"}) {
		t.Errorf("live = %v", ids)
	}
	if after["CVE-2024-0002"] != before["CVE-2024-0002"] {
		t.Error("kept item was re-created")
	}
}

func TestReplaceWatchlistItems_ReaddedItemIsNewRow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace4")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001"))
	first := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)["CVE-2024-0001"]
	mustReplace(t, s.Store, ctx, org.ID, w.ID, nil)
	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001"))

	if want := (store.ReplaceWatchlistItemsResult{Added: 1}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
	if second := liveCVEIDs(t, s.Store, ctx, org.ID, w.ID)["CVE-2024-0001"]; second == first {
		t.Error("re-added item reused the soft-deleted row")
	}
}

func TestReplaceWatchlistItems_EmptyListClears(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace5")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001", "CVE-2024-0002"))
	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, []store.CreateWatchlistItemParams{})

	if want := (store.ReplaceWatchlistItemsResult{Removed: 2}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
	count, err := s.CountWatchlistItems(ctx, org.ID, w.ID)
	if err != nil {
		t.Fatalf("CountWatchlistItems: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestReplaceWatchlistItems_RepeatedItemCountsOnce(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace6")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	got := mustReplace(t, s.Store, ctx, org.ID, w.ID, cveItems("CVE-2024-0001", "CVE-2024-0001"))

	if want := (store.ReplaceWatchlistItemsResult{Added: 1}); got != want {
		t.Errorf("result = %+v, want %+v", got, want)
	}
}

func TestReplaceWatchlistItems_AllItemTypes(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace7")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "Mixed")
	items := []store.CreateWatchlistItemParams{
		{ItemType: "package", Ecosystem: strPtr("npm"), PackageName: strPtr("express"), Namespace: strPtr("@acme")},
		{ItemType: "package", Ecosystem: strPtr("pypi"), PackageName: strPtr("django")},
		{ItemType: "cpe", CpeNormalized: strPtr("cpe:2.3:a:apache:log4j")},
		cveItem("CVE-2024-0001"),
	}

	if got, want := mustReplace(t, s.Store, ctx, org.ID, w.ID, items), (store.ReplaceWatchlistItemsResult{Added: 4}); got != want {
		t.Fatalf("first replace = %+v, want %+v", got, want)
	}
	if got, want := mustReplace(t, s.Store, ctx, org.ID, w.ID, items), (store.ReplaceWatchlistItemsResult{Unchanged: 4}); got != want {
		t.Fatalf("second replace = %+v, want %+v", got, want)
	}

	listed, err := s.ListWatchlistItems(ctx, org.ID, w.ID, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListWatchlistItems: %v", err)
	}
	var withNamespace, withoutNamespace int
	for _, item := range listed {
		switch {
		case item.ItemType == "package" && item.Namespace.String == "@acme":
			withNamespace++
		case item.ItemType == "package" && !item.Namespace.Valid:
			withoutNamespace++
		}
	}
	if withNamespace != 1 || withoutNamespace != 1 {
		t.Errorf("package items: %d with namespace and %d with NULL namespace, want 1 and 1", withNamespace, withoutNamespace)
	}

	// A package whose namespace changed is a different item, replaced in place.
	items[0].Namespace = strPtr("@other")
	if got, want := mustReplace(t, s.Store, ctx, org.ID, w.ID, items), (store.ReplaceWatchlistItemsResult{Added: 1, Removed: 1, Unchanged: 3}); got != want {
		t.Errorf("namespace change = %+v, want %+v", got, want)
	}
}

func TestReplaceWatchlistItems_SoftDeletedWatchlistNotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace8")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "Gone")
	if err := s.DeleteWatchlist(ctx, org.ID, w.ID); err != nil {
		t.Fatalf("DeleteWatchlist: %v", err)
	}

	result, err := s.ReplaceWatchlistItems(ctx, org.ID, w.ID, cveItems("CVE-2024-0001"))
	if err != nil {
		t.Fatalf("ReplaceWatchlistItems: %v", err)
	}
	if result != nil {
		t.Errorf("result = %+v, want nil for a soft-deleted watchlist", *result)
	}
}

// TestReplaceWatchlistItems_AppRoleTenantIsolation runs as cvert_ops_app, so the only
// things between the two orgs are the org_id parameter and the RLS policies.
func TestReplaceWatchlistItems_AppRoleTenantIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	victim := s.MustCreateOrg(t, ctx, "WLVictim")
	other := s.MustCreateOrg(t, ctx, "WLOther")
	w := mustCreateWatchlist(t, s, ctx, victim.ID, "Victim list")

	// The app role can replace its own org's list: the grants cover every statement.
	if got, want := mustReplace(t, s.AppStore, ctx, victim.ID, w.ID, cveItems("CVE-2024-0001")), (store.ReplaceWatchlistItemsResult{Added: 1}); got != want {
		t.Fatalf("own replace = %+v, want %+v", got, want)
	}

	result, err := s.AppStore.ReplaceWatchlistItems(ctx, other.ID, w.ID, cveItems("CVE-2024-9999"))
	if err != nil {
		t.Fatalf("cross-org ReplaceWatchlistItems: %v", err)
	}
	if result != nil {
		t.Errorf("cross-org replace = %+v, want nil", *result)
	}
	if read := liveCVEIDs(t, s.AppStore, ctx, other.ID, w.ID); len(read) != 0 {
		t.Errorf("cross-org read returned %v", read)
	}

	// Under the victim's org_id setting the row is still exactly what the victim wrote.
	live := liveCVEIDs(t, s.AppStore, ctx, victim.ID, w.ID)
	if _, ok := live["CVE-2024-0001"]; !ok || len(live) != 1 {
		t.Errorf("victim list after cross-org attempt = %v", live)
	}

	// The RLS policy alone hides another org's rows from the query that feeds the diff.
	tx, err := s.AppStore.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // read-only transaction
	if _, err := tx.ExecContext(ctx, `SELECT set_config('app.org_id', $1, true)`, other.ID.String()); err != nil {
		t.Fatalf("set app.org_id: %v", err)
	}
	var visible int
	if err := tx.QueryRowContext(ctx,
		`SELECT count(*) FROM watchlist_items WHERE watchlist_id = $1`, w.ID).Scan(&visible); err != nil {
		t.Fatalf("count under other org: %v", err)
	}
	if visible != 0 {
		t.Errorf("RLS exposed %d of another org's rows", visible)
	}
}

// TestReplaceWatchlistItems_ConcurrentCallsSerialize checks the watchlist row lock: without
// it, two calls that both read an empty list would both insert the same CVE and one would
// fail on the unique index.
func TestReplaceWatchlistItems_ConcurrentCallsSerialize(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()
	org := s.MustCreateOrg(t, ctx, "WLReplace9")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CVEs")

	ids := make([]string, 0, 200)
	for i := range 200 {
		ids = append(ids, fmt.Sprintf("CVE-2024-%04d", i))
	}
	items := cveItems(ids...)

	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.ReplaceWatchlistItems(ctx, org.ID, w.ID, items)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("call %d: %v", i, err)
		}
	}
	count, err := s.CountWatchlistItems(ctx, org.ID, w.ID)
	if err != nil {
		t.Fatalf("CountWatchlistItems: %v", err)
	}
	if count != 200 {
		t.Errorf("count = %d, want 200", count)
	}
}
