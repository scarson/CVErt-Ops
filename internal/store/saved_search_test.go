// ABOUTME: Integration tests for saved search CRUD with soft-delete, visibility filtering.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestSavedSearch_Create(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSCreateOrg")
	user, _ := s.CreateUser(ctx, "sscreate@example.com", "SSCreate", "", 0)

	row, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "My Search",
		QueryJSON: json.RawMessage(`{"keywords":"log4j"}`),
		NlQuery:   strPtr("find log4j vulnerabilities"),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch: %v", err)
	}
	if row.Name != "My Search" {
		t.Errorf("Name = %q, want %q", row.Name, "My Search")
	}
	if row.OrgID != org.ID {
		t.Errorf("OrgID = %v, want %v", row.OrgID, org.ID)
	}
	if !row.UserID.Valid || row.UserID.UUID != user.ID {
		t.Errorf("UserID = %v, want %v", row.UserID, user.ID)
	}
	if row.IsShared {
		t.Error("IsShared = true, want false")
	}
	if !row.NlQuery.Valid || row.NlQuery.String != "find log4j vulnerabilities" {
		t.Errorf("NlQuery = %v, want 'find log4j vulnerabilities'", row.NlQuery)
	}
	var gotQuery map[string]string
	if err := json.Unmarshal(row.QueryJSON, &gotQuery); err != nil {
		t.Fatalf("unmarshal QueryJSON: %v", err)
	}
	if gotQuery["keywords"] != "log4j" {
		t.Errorf("QueryJSON[keywords] = %q, want log4j", gotQuery["keywords"])
	}
	if row.ID == uuid.Nil {
		t.Error("ID should not be nil")
	}
	if row.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
	if row.DeletedAt.Valid {
		t.Error("DeletedAt should be NULL for a new record")
	}
}

func TestSavedSearch_Get(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSGetOrg")
	user, _ := s.CreateUser(ctx, "ssget@example.com", "SSGet", "", 0)

	created, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "Get Test",
		QueryJSON: json.RawMessage(`{"severity":"critical"}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch: %v", err)
	}

	got, err := s.GetSavedSearch(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetSavedSearch: %v", err)
	}
	if got == nil {
		t.Fatal("GetSavedSearch returned nil for existing record")
	}
	if got.ID != created.ID {
		t.Errorf("ID = %v, want %v", got.ID, created.ID)
	}
	if got.Name != "Get Test" {
		t.Errorf("Name = %q, want %q", got.Name, "Get Test")
	}
}

func TestSavedSearch_Get_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSGetNFOrg")

	got, err := s.GetSavedSearch(ctx, org.ID, uuid.New())
	if err != nil {
		t.Fatalf("GetSavedSearch(not found): %v", err)
	}
	if got != nil {
		t.Error("GetSavedSearch should return nil for nonexistent ID")
	}
}

func TestSavedSearch_Update(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSUpdateOrg")
	user, _ := s.CreateUser(ctx, "ssupdate@example.com", "SSUpdate", "", 0)

	created, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "Original Name",
		QueryJSON: json.RawMessage(`{"q":"old"}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch: %v", err)
	}

	updated, err := s.UpdateSavedSearch(ctx, org.ID, created.ID, store.UpdateSavedSearchParams{
		Name:      "Renamed",
		QueryJSON: json.RawMessage(`{"q":"new"}`),
		IsShared:  true,
	})
	if err != nil {
		t.Fatalf("UpdateSavedSearch: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateSavedSearch returned nil")
	}
	if updated.Name != "Renamed" {
		t.Errorf("Name = %q, want Renamed", updated.Name)
	}
	if !updated.IsShared {
		t.Error("IsShared = false, want true")
	}
	var updatedQuery map[string]string
	if err := json.Unmarshal(updated.QueryJSON, &updatedQuery); err != nil {
		t.Fatalf("unmarshal updated QueryJSON: %v", err)
	}
	if updatedQuery["q"] != "new" {
		t.Errorf("QueryJSON[q] = %q, want new", updatedQuery["q"])
	}
}

func TestSavedSearch_SoftDelete(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSDeleteOrg")
	user, _ := s.CreateUser(ctx, "ssdelete@example.com", "SSDelete", "", 0)

	created, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "To Delete",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch: %v", err)
	}

	if err := s.SoftDeleteSavedSearch(ctx, org.ID, created.ID); err != nil {
		t.Fatalf("SoftDeleteSavedSearch: %v", err)
	}

	got, err := s.GetSavedSearch(ctx, org.ID, created.ID)
	if err != nil {
		t.Fatalf("GetSavedSearch(after delete): %v", err)
	}
	if got != nil {
		t.Error("GetSavedSearch should return nil for soft-deleted record")
	}
}

func TestSavedSearch_List_Private(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSListPrivOrg")
	user1, _ := s.CreateUser(ctx, "sslist1@example.com", "SSList1", "", 0)
	user2, _ := s.CreateUser(ctx, "sslist2@example.com", "SSList2", "", 0)

	// User1 creates a private search.
	_, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user1.ID, Valid: true},
		Name:      "User1 Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (user1 private): %v", err)
	}

	// User2 creates a private search.
	_, err = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user2.ID, Valid: true},
		Name:      "User2 Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (user2 private): %v", err)
	}

	// User1 lists with visibility=private — should only see their own.
	rows, err := s.ListSavedSearches(ctx, org.ID, user1.ID, "private", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(private, user1): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 private search for user1, got %d", len(rows))
	}
	if rows[0].Name != "User1 Private" {
		t.Errorf("Name = %q, want User1 Private", rows[0].Name)
	}
}

func TestSavedSearch_List_Shared(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSListSharedOrg")
	user1, _ := s.CreateUser(ctx, "ssshared1@example.com", "SSShared1", "", 0)
	user2, _ := s.CreateUser(ctx, "ssshared2@example.com", "SSShared2", "", 0)

	// User1 creates a shared search.
	_, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user1.ID, Valid: true},
		Name:      "Shared Search",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  true,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (shared): %v", err)
	}

	// User1 creates a private search.
	_, err = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user1.ID, Valid: true},
		Name:      "Private Search",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (private): %v", err)
	}

	// User2 lists shared — should see only the shared search.
	rows, err := s.ListSavedSearches(ctx, org.ID, user2.ID, "shared", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(shared, user2): %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 shared search visible to user2, got %d", len(rows))
	}
	if rows[0].Name != "Shared Search" {
		t.Errorf("Name = %q, want Shared Search", rows[0].Name)
	}
}

func TestSavedSearch_List_Visibility_Filter(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSListVisOrg")
	user1, _ := s.CreateUser(ctx, "ssvis1@example.com", "SSVis1", "", 0)
	user2, _ := s.CreateUser(ctx, "ssvis2@example.com", "SSVis2", "", 0)

	// User1: one private, one shared.
	_, _ = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user1.ID, Valid: true},
		Name:      "U1 Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	_, _ = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user1.ID, Valid: true},
		Name:      "U1 Shared",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  true,
	})

	// User2: one private.
	_, _ = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user2.ID, Valid: true},
		Name:      "U2 Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})

	// "all" for user1: should see U1 Private + U1 Shared (own private + all shared).
	all, err := s.ListSavedSearches(ctx, org.ID, user1.ID, "all", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(all, user1): %v", err)
	}
	if len(all) != 2 {
		t.Errorf("user1 all: got %d, want 2", len(all))
	}

	// "all" for user2: should see U2 Private + U1 Shared.
	all2, err := s.ListSavedSearches(ctx, org.ID, user2.ID, "all", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(all, user2): %v", err)
	}
	if len(all2) != 2 {
		t.Errorf("user2 all: got %d, want 2", len(all2))
	}

	// "private" for user2: only U2 Private.
	priv, err := s.ListSavedSearches(ctx, org.ID, user2.ID, "private", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(private, user2): %v", err)
	}
	if len(priv) != 1 {
		t.Errorf("user2 private: got %d, want 1", len(priv))
	}

	// "shared" for user2: only U1 Shared.
	shared, err := s.ListSavedSearches(ctx, org.ID, user2.ID, "shared", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches(shared, user2): %v", err)
	}
	if len(shared) != 1 {
		t.Errorf("user2 shared: got %d, want 1", len(shared))
	}
	if shared[0].Name != "U1 Shared" {
		t.Errorf("shared Name = %q, want U1 Shared", shared[0].Name)
	}
}

func TestSavedSearch_CleanupOrphanedPrivate(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "SSCleanupOrg")
	user, _ := s.CreateUser(ctx, "sscleanup@example.com", "SSCleanup", "", 0)
	otherUser, _ := s.CreateUser(ctx, "ssother@example.com", "SSOther", "", 0)

	// User's private search.
	_, err := s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "User Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (user private): %v", err)
	}

	// User's shared search (should NOT be deleted).
	_, err = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: user.ID, Valid: true},
		Name:      "User Shared",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  true,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (user shared): %v", err)
	}

	// Other user's private search (should NOT be deleted).
	_, err = s.CreateSavedSearch(ctx, org.ID, store.CreateSavedSearchParams{
		UserID:    uuid.NullUUID{UUID: otherUser.ID, Valid: true},
		Name:      "Other Private",
		QueryJSON: json.RawMessage(`{}`),
		IsShared:  false,
	})
	if err != nil {
		t.Fatalf("CreateSavedSearch (other private): %v", err)
	}

	// Cleanup orphaned private searches for user.
	if err := s.CleanupOrphanedPrivateSavedSearches(ctx, user.ID); err != nil {
		t.Fatalf("CleanupOrphanedPrivateSavedSearches: %v", err)
	}

	// User's shared search should still exist.
	remaining, err := s.ListSavedSearches(ctx, org.ID, user.ID, "all", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches after cleanup: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("expected 1 remaining search for user (shared only), got %d", len(remaining))
	}
	if remaining[0].Name != "User Shared" {
		t.Errorf("remaining Name = %q, want User Shared", remaining[0].Name)
	}

	// Other user's private search should still exist.
	otherRemaining, err := s.ListSavedSearches(ctx, org.ID, otherUser.ID, "private", 200)
	if err != nil {
		t.Fatalf("ListSavedSearches (other user private): %v", err)
	}
	if len(otherRemaining) != 1 {
		t.Fatalf("expected 1 private search for other user, got %d", len(otherRemaining))
	}
	if otherRemaining[0].Name != "Other Private" {
		t.Errorf("other remaining Name = %q, want Other Private", otherRemaining[0].Name)
	}
}
