// ABOUTME: Integration tests for org tier queries — GetOrgTier, UpdateOrgTier, counts.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/store"
	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestGetOrgTier(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := db.CreateOrg(ctx, "TierOrg1")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	tier, overrides, err := db.GetOrgTier(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrgTier: %v", err)
	}
	if tier != "free" {
		t.Errorf("default tier = %q, want %q", tier, "free")
	}
	if len(overrides) != 0 {
		t.Errorf("default overrides = %v, want empty", overrides)
	}
}

func TestUpdateOrgTier(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "TierOrg2")

	if err := db.UpdateOrgTier(ctx, org.ID, "pro"); err != nil {
		t.Fatalf("UpdateOrgTier: %v", err)
	}

	tier, _, err := db.GetOrgTier(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrgTier after update: %v", err)
	}
	if tier != "pro" {
		t.Errorf("tier after update = %q, want %q", tier, "pro")
	}
}

func TestCountAlertRulesByOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "CountRulesOrg")
	user, _ := db.CreateUser(ctx, "countru@example.com", "Counter", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "owner")

	// Create two active rules via AppStore (RLS-constrained).
	for i := 0; i < 2; i++ {
		_, err := db.AppStore.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
			Name:       fmt.Sprintf("Rule %d", i),
			Logic:      "and",
			Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"critical"}]`),
			Status:     "active",
		})
		if err != nil {
			t.Fatalf("CreateAlertRule %d: %v", i, err)
		}
	}

	// Create and soft-delete a third rule.
	deleted, err := db.AppStore.CreateAlertRule(ctx, org.ID, store.CreateAlertRuleParams{
		Name:       "Deleted Rule",
		Logic:      "and",
		Conditions: json.RawMessage(`[{"field":"severity","operator":"eq","value":"high"}]`),
		Status:     "active",
	})
	if err != nil {
		t.Fatalf("CreateAlertRule (to delete): %v", err)
	}
	if err := db.AppStore.SoftDeleteAlertRule(ctx, org.ID, deleted.ID); err != nil {
		t.Fatalf("SoftDeleteAlertRule: %v", err)
	}

	// Count via AppStore (org-scoped, RLS active).
	count, err := db.AppStore.CountAlertRulesByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountAlertRulesByOrg: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (soft-deleted excluded)", count)
	}
}

func TestCountWatchlistsByOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "CountWLOrg")
	user, _ := db.CreateUser(ctx, "countwl@example.com", "Counter", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "owner")

	// Create two watchlists.
	for i := 0; i < 2; i++ {
		_, err := db.AppStore.CreateWatchlist(ctx, org.ID, uuid.NullUUID{}, fmt.Sprintf("WL %d", i), sql.NullString{})
		if err != nil {
			t.Fatalf("CreateWatchlist %d: %v", i, err)
		}
	}

	// Create and soft-delete a third.
	del, err := db.AppStore.CreateWatchlist(ctx, org.ID, uuid.NullUUID{}, "DelWL", sql.NullString{})
	if err != nil {
		t.Fatalf("CreateWatchlist (to delete): %v", err)
	}
	if err := db.AppStore.DeleteWatchlist(ctx, org.ID, del.ID); err != nil {
		t.Fatalf("DeleteWatchlist: %v", err)
	}

	count, err := db.AppStore.CountWatchlistsByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountWatchlistsByOrg: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2 (soft-deleted excluded)", count)
	}
}

func TestCountMembersByOrg(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := db.CreateOrg(ctx, "CountMemOrg")
	user, _ := db.CreateUser(ctx, "countm@example.com", "Counter", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user.ID, "owner")

	// Org creator = 1 member.
	count, err := db.AppStore.CountMembersByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountMembersByOrg: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1 (org creator)", count)
	}

	// Add another member.
	user2, _ := db.CreateUser(ctx, "countm2@example.com", "Counter2", "", 0)
	_ = db.CreateOrgMember(ctx, org.ID, user2.ID, "member")

	count, err = db.AppStore.CountMembersByOrg(ctx, org.ID)
	if err != nil {
		t.Fatalf("CountMembersByOrg after add: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestListAllOrgs(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs with different tiers.
	org1, _ := db.CreateOrg(ctx, "AllOrg1")
	org2, _ := db.CreateOrg(ctx, "AllOrg2")
	_ = db.UpdateOrgTier(ctx, org2.ID, "enterprise")

	// ListAllOrgs uses bypass (cross-org) — called via embedded Store.
	orgs, err := db.ListAllOrgs(ctx)
	if err != nil {
		t.Fatalf("ListAllOrgs: %v", err)
	}
	if len(orgs) < 2 {
		t.Fatalf("ListAllOrgs returned %d orgs, want >= 2", len(orgs))
	}

	found := map[uuid.UUID]string{}
	for _, o := range orgs {
		found[o.ID] = o.Tier
	}
	if found[org1.ID] != "free" {
		t.Errorf("org1 tier = %q, want free", found[org1.ID])
	}
	if found[org2.ID] != "enterprise" {
		t.Errorf("org2 tier = %q, want enterprise", found[org2.ID])
	}
}
