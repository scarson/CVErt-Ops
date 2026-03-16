// ABOUTME: Cross-tenant RLS isolation integration test.
// ABOUTME: Proves that org-scoped queries via the NOBYPASSRLS connection cannot see other orgs' data.
package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestRLS_CrossTenantBlocked(t *testing.T) {
	t.Parallel()
	tdb := testutil.NewTestDB(t)

	ctx := context.Background()

	// Create two orgs via the superuser connection (tdb embeds *store.Store).
	org1, err := tdb.CreateOrg(ctx, "RLS Test Org 1")
	if err != nil {
		t.Fatalf("setup: CreateOrg org1: %v", err)
	}
	org2, err := tdb.CreateOrg(ctx, "RLS Test Org 2")
	if err != nil {
		t.Fatalf("setup: CreateOrg org2: %v", err)
	}

	// Create a watchlist in org1 via the superuser connection.
	_, err = tdb.CreateWatchlist(ctx, org1.ID, uuid.NullUUID{}, "Org1 Secret List", sql.NullString{})
	if err != nil {
		t.Fatalf("setup: CreateWatchlist in org1: %v", err)
	}

	// Also create a watchlist in org2 so we can verify each org sees only its own.
	_, err = tdb.CreateWatchlist(ctx, org2.ID, uuid.NullUUID{}, "Org2 Own List", sql.NullString{})
	if err != nil {
		t.Fatalf("setup: CreateWatchlist in org2: %v", err)
	}

	// Query through the RESTRICTED connection (tdb.AppStore) scoped to org2.
	// tdb.AppStore uses the NOBYPASSRLS database role — if RLS is broken,
	// this query could return org1's data alongside org2's.
	got, err := tdb.AppStore.ListWatchlists(ctx, org2.ID, nil, nil, 100)
	if err != nil {
		t.Fatalf("AppStore.ListWatchlists(org2): %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected exactly 1 watchlist for org2, got %d — RLS isolation failure", len(got))
	} else if got[0].Name != "Org2 Own List" {
		t.Errorf("expected org2's own watchlist, got %q", got[0].Name)
	}

	// Cross-check: org1 via the restricted connection should see only its own.
	got1, err := tdb.AppStore.ListWatchlists(ctx, org1.ID, nil, nil, 100)
	if err != nil {
		t.Fatalf("AppStore.ListWatchlists(org1): %v", err)
	}
	if len(got1) != 1 {
		t.Errorf("expected exactly 1 watchlist for org1, got %d — RLS isolation failure", len(got1))
	} else if got1[0].Name != "Org1 Secret List" {
		t.Errorf("expected org1's own watchlist, got %q", got1[0].Name)
	}
}
