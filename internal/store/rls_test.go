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

	// Query through the RESTRICTED connection (tdb.AppStore) scoped to org2.
	// tdb.AppStore uses the NOBYPASSRLS database role — if RLS is broken,
	// this query returns org1's data. If RLS works, it returns empty.
	got, err := tdb.AppStore.ListWatchlists(ctx, org2.ID, nil, nil, 100)
	if err != nil {
		t.Fatalf("AppStore.ListWatchlists(org2): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 watchlists for org2, got %d — RLS cross-tenant leak detected", len(got))
	}
}
