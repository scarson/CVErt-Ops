// ABOUTME: Integration tests for store/watchlist.go -- watchlist and item CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func mustCreateWatchlist(t *testing.T, s *testutil.TestDB, ctx context.Context, orgID uuid.UUID, name string) *store.WatchlistRow {
	t.Helper()
	w, err := s.CreateWatchlist(ctx, orgID, uuid.NullUUID{}, name, sql.NullString{})
	if err != nil {
		t.Fatalf("CreateWatchlist(%q): %v", name, err)
	}
	return w
}

func TestCreateAndGetWatchlist(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg1")

	w, err := s.CreateWatchlist(ctx, org.ID, uuid.NullUUID{}, "My List", sql.NullString{Valid: true, String: "desc"})
	if err != nil {
		t.Fatalf("CreateWatchlist: %v", err)
	}
	if w.Name != "My List" {
		t.Errorf("Name = %q, want %q", w.Name, "My List")
	}
	if !w.Description.Valid || w.Description.String != "desc" {
		t.Errorf("Description = %v, want desc", w.Description)
	}
	if w.ItemCount != 0 {
		t.Errorf("ItemCount = %d, want 0", w.ItemCount)
	}

	got, err := s.GetWatchlist(ctx, org.ID, w.ID)
	if err != nil {
		t.Fatalf("GetWatchlist: %v", err)
	}
	if got == nil {
		t.Fatal("GetWatchlist returned nil for existing watchlist")
	}
	if got.ID != w.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, w.ID)
	}
}

func TestGetWatchlist_WrongOrgReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "WLOrg2a")
	org2, _ := s.CreateOrg(ctx, "WLOrg2b")
	w := mustCreateWatchlist(t, s, ctx, org1.ID, "List A")

	got, err := s.GetWatchlist(ctx, org2.ID, w.ID)
	if err != nil {
		t.Fatalf("GetWatchlist(wrong org): %v", err)
	}
	if got != nil {
		t.Error("GetWatchlist with wrong org should return nil")
	}
}

func TestSoftDeleteWatchlist(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg3")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "ToDelete")

	if err := s.DeleteWatchlist(ctx, org.ID, w.ID); err != nil {
		t.Fatalf("DeleteWatchlist: %v", err)
	}

	got, err := s.GetWatchlist(ctx, org.ID, w.ID)
	if err != nil {
		t.Fatalf("GetWatchlist(deleted): %v", err)
	}
	if got != nil {
		t.Error("GetWatchlist should return nil for soft-deleted watchlist")
	}
}

func TestUpdateWatchlist(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg4")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "Original")

	updated, err := s.UpdateWatchlist(ctx, org.ID, w.ID, store.UpdateWatchlistParams{
		Name:        "Renamed",
		Description: sql.NullString{Valid: true, String: "new desc"},
		GroupID:     uuid.NullUUID{},
	})
	if err != nil {
		t.Fatalf("UpdateWatchlist: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateWatchlist returned nil")
	}
	if updated.Name != "Renamed" {
		t.Errorf("Name = %q, want Renamed", updated.Name)
	}
}

func TestUpdateWatchlist_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg4b")

	updated, err := s.UpdateWatchlist(ctx, org.ID, uuid.New(), store.UpdateWatchlistParams{Name: "X"})
	if err != nil {
		t.Fatalf("UpdateWatchlist(not found): %v", err)
	}
	if updated != nil {
		t.Error("UpdateWatchlist on non-existent id should return nil")
	}
}

func TestCreateWatchlistItem_Package(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg5")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "PkgList")

	item, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{
		ItemType:    "package",
		Ecosystem:   strPtr("npm"),
		PackageName: strPtr("express"),
	})
	if err != nil {
		t.Fatalf("CreateWatchlistItem(package): %v", err)
	}
	if item.ItemType != "package" {
		t.Errorf("ItemType = %q, want package", item.ItemType)
	}
	if !item.Ecosystem.Valid || item.Ecosystem.String != "npm" {
		t.Errorf("Ecosystem = %v, want npm", item.Ecosystem)
	}

	count, err := s.CountWatchlistItems(ctx, org.ID, w.ID)
	if err != nil {
		t.Fatalf("CountWatchlistItems: %v", err)
	}
	if count != 1 {
		t.Errorf("ItemCount = %d, want 1", count)
	}
}

func TestCreateWatchlistItem_CPE(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg6")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "CPEList")

	item, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{
		ItemType:      "cpe",
		CpeNormalized: strPtr("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
	})
	if err != nil {
		t.Fatalf("CreateWatchlistItem(cpe): %v", err)
	}
	if item.ItemType != "cpe" {
		t.Errorf("ItemType = %q, want cpe", item.ItemType)
	}
}

func TestCreateWatchlistItem_DuplicateConflict(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg7")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "DupList")

	p := store.CreateWatchlistItemParams{
		ItemType:    "package",
		Ecosystem:   strPtr("npm"),
		PackageName: strPtr("lodash"),
	}
	if _, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, p); err != nil {
		t.Fatalf("CreateWatchlistItem (first): %v", err)
	}
	_, err := s.CreateWatchlistItem(ctx, org.ID, w.ID, p)
	if err == nil {
		t.Error("expected error on duplicate package item, got nil")
	}
}

func TestDeleteWatchlistItem(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg8")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "ItemDel")

	item, _ := s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{
		ItemType:    "package",
		Ecosystem:   strPtr("pypi"),
		PackageName: strPtr("requests"),
	})

	if err := s.DeleteWatchlistItem(ctx, org.ID, w.ID, item.ID); err != nil {
		t.Fatalf("DeleteWatchlistItem: %v", err)
	}

	count, _ := s.CountWatchlistItems(ctx, org.ID, w.ID)
	if count != 0 {
		t.Errorf("ItemCount after delete = %d, want 0", count)
	}
}

func TestListWatchlistItems_ItemTypeFilter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg9")
	w := mustCreateWatchlist(t, s, ctx, org.ID, "MixedList")

	_, _ = s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{
		ItemType: "cpe", CpeNormalized: strPtr("cpe:2.3:a:a:b:1.0:*:*:*:*:*:*:*"),
	})
	_, _ = s.CreateWatchlistItem(ctx, org.ID, w.ID, store.CreateWatchlistItemParams{
		ItemType: "package", Ecosystem: strPtr("npm"), PackageName: strPtr("axios"),
	})

	pkgType := store.WatchlistItemType("package")
	itemsAll, err := s.ListWatchlistItems(ctx, org.ID, w.ID, nil, nil, 10)
	if err != nil {
		t.Fatalf("ListWatchlistItems(all): %v", err)
	}
	if len(itemsAll) != 2 {
		t.Errorf("all items: got %d, want 2", len(itemsAll))
	}

	pkgItems, err := s.ListWatchlistItems(ctx, org.ID, w.ID, &pkgType, nil, 10)
	if err != nil {
		t.Fatalf("ListWatchlistItems(package): %v", err)
	}
	if len(pkgItems) != 1 {
		t.Errorf("package items: got %d, want 1", len(pkgItems))
	}
	if pkgItems[0].ItemType != "package" {
		t.Errorf("ItemType = %q, want package", pkgItems[0].ItemType)
	}
}

func TestListWatchlists_KeysetPagination(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "WLOrg10")
	for range 5 {
		mustCreateWatchlist(t, s, ctx, org.ID, uuid.NewString())
	}

	page1, err := s.ListWatchlists(ctx, org.ID, nil, nil, 3)
	if err != nil {
		t.Fatalf("ListWatchlists(page1): %v", err)
	}
	if len(page1) != 3 {
		t.Fatalf("page1: got %d items, want 3", len(page1))
	}

	last := page1[len(page1)-1]
	page2, err := s.ListWatchlists(ctx, org.ID, &last.CreatedAt, &last.ID, 3)
	if err != nil {
		t.Fatalf("ListWatchlists(page2): %v", err)
	}
	if len(page2) != 2 {
		t.Fatalf("page2: got %d items, want 2", len(page2))
	}

	seen := map[uuid.UUID]bool{}
	for _, w := range page1 {
		seen[w.ID] = true
	}
	for _, w := range page2 {
		if seen[w.ID] {
			t.Errorf("overlap: %v appeared in both pages", w.ID)
		}
	}
}

func TestValidateWatchlistsOwnership(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "WLOrg11a")
	org2, _ := s.CreateOrg(ctx, "WLOrg11b")
	w1 := mustCreateWatchlist(t, s, ctx, org1.ID, "Org1List")
	w2 := mustCreateWatchlist(t, s, ctx, org2.ID, "Org2List")

	ok, err := s.ValidateWatchlistsOwnership(ctx, org1.ID, []uuid.UUID{w1.ID})
	if err != nil {
		t.Fatalf("ValidateWatchlistsOwnership (owned): %v", err)
	}
	if !ok {
		t.Error("expected true for owned watchlist")
	}

	ok2, err := s.ValidateWatchlistsOwnership(ctx, org1.ID, []uuid.UUID{w1.ID, w2.ID})
	if err != nil {
		t.Fatalf("ValidateWatchlistsOwnership (cross-org): %v", err)
	}
	if ok2 {
		t.Error("expected false when cross-org watchlist included")
	}

	ok3, err := s.ValidateWatchlistsOwnership(ctx, org1.ID, nil)
	if err != nil {
		t.Fatalf("ValidateWatchlistsOwnership (empty): %v", err)
	}
	if !ok3 {
		t.Error("expected true for empty watchlist slice")
	}
}

// strPtr returns a pointer to s.
func strPtr(s string) *string { return &s }

// Silence unused import.
var _ = time.Time{}
