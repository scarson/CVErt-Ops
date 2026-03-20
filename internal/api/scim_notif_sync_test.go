// ABOUTME: Integration tests for notification group sync from SCIM group mappings.
// ABOUTME: Uses real Postgres via testutil.NewTestDB to exercise the full store path.
package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// findGroupMember searches the group members list for the given userID.
// Returns (scim_managed, found).
func findGroupMember(t *testing.T, db *testutil.TestDB, ctx context.Context, orgID, groupID, userID uuid.UUID) (scimManaged, found bool) {
	t.Helper()
	members, err := db.ListGroupMembers(ctx, orgID, groupID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	for _, m := range members {
		if m.UserID == userID {
			return m.ScimManaged, true
		}
	}
	return false, false
}

func TestNotifSync_Add_NewMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-add-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	if err := srv.syncNotifGroupAdd(ctx, org.ID, user.ID, notifGroup.ID, scimGroup.ID); err != nil {
		t.Fatalf("syncNotifGroupAdd: %v", err)
	}

	scimManaged, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if !found {
		t.Fatal("user should be a member of the notification group")
	}
	if !scimManaged {
		t.Error("membership should be scim_managed=true")
	}
}

func TestNotifSync_Add_AlreadyManualMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-manual-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	// Add as manual member first (scim_managed=false).
	if err := db.AddGroupMember(ctx, org.ID, notifGroup.ID, user.ID); err != nil {
		t.Fatalf("setup: AddGroupMember: %v", err)
	}

	// SCIM sync should not overwrite manual membership.
	if err := srv.syncNotifGroupAdd(ctx, org.ID, user.ID, notifGroup.ID, scimGroup.ID); err != nil {
		t.Fatalf("syncNotifGroupAdd: %v", err)
	}

	scimManaged, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if !found {
		t.Fatal("user should still be a member")
	}
	if scimManaged {
		t.Error("scim_managed should remain false (manual membership takes precedence)")
	}
}

func TestNotifSync_Remove_SCIMManaged(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-rm-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	// Add via SCIM (scim_managed=true).
	if err := db.AddGroupMemberSCIMManaged(ctx, notifGroup.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddGroupMemberSCIMManaged: %v", err)
	}

	if err := srv.syncNotifGroupRemove(ctx, org.ID, user.ID, notifGroup.ID, scimGroup.ID); err != nil {
		t.Fatalf("syncNotifGroupRemove: %v", err)
	}

	_, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if found {
		t.Error("user should have been removed from the notification group")
	}
}

func TestNotifSync_Remove_ManualMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-rm-manual-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	// Add as manual member (scim_managed=false).
	if err := db.AddGroupMember(ctx, org.ID, notifGroup.ID, user.ID); err != nil {
		t.Fatalf("setup: AddGroupMember: %v", err)
	}

	// SCIM removal should not affect manual membership.
	if err := srv.syncNotifGroupRemove(ctx, org.ID, user.ID, notifGroup.ID, scimGroup.ID); err != nil {
		t.Fatalf("syncNotifGroupRemove: %v", err)
	}

	_, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if !found {
		t.Error("manual member should not be removed by SCIM sync")
	}
}

func TestNotifSync_Remove_MultiMapping(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-multi-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")

	// Two SCIM groups, both mapped to the same notification group.
	scimGroupA, err := db.CreateSCIMGroup(ctx, org.ID, nil, "GroupA")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup A: %v", err)
	}
	scimGroupB, err := db.CreateSCIMGroup(ctx, org.ID, nil, "GroupB")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup B: %v", err)
	}

	// Map both SCIM groups to the same notification group.
	notifGroupID := notifGroup.ID
	if err := db.UpdateSCIMGroupMapping(ctx, org.ID, scimGroupA.ID, nil, &notifGroupID); err != nil {
		t.Fatalf("setup: UpdateSCIMGroupMapping A: %v", err)
	}
	if err := db.UpdateSCIMGroupMapping(ctx, org.ID, scimGroupB.ID, nil, &notifGroupID); err != nil {
		t.Fatalf("setup: UpdateSCIMGroupMapping B: %v", err)
	}

	// Add user to both SCIM groups.
	if err := db.AddSCIMGroupMember(ctx, scimGroupA.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddSCIMGroupMember A: %v", err)
	}
	if err := db.AddSCIMGroupMember(ctx, scimGroupB.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddSCIMGroupMember B: %v", err)
	}

	// Add SCIM-managed membership to notification group.
	if err := db.AddGroupMemberSCIMManaged(ctx, notifGroup.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddGroupMemberSCIMManaged: %v", err)
	}

	// Remove from SCIM group A — user still in group B with same mapping.
	if err := srv.syncNotifGroupRemove(ctx, org.ID, user.ID, notifGroup.ID, scimGroupA.ID); err != nil {
		t.Fatalf("syncNotifGroupRemove (A): %v", err)
	}
	_, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if !found {
		t.Fatal("user should still be a member (another SCIM group maps to the same notification group)")
	}

	// Now remove from SCIM group B — no more mappings, should remove.
	if err := db.RemoveSCIMGroupMember(ctx, org.ID, scimGroupA.ID, user.ID); err != nil {
		t.Fatalf("RemoveSCIMGroupMember A: %v", err)
	}
	if err := srv.syncNotifGroupRemove(ctx, org.ID, user.ID, notifGroup.ID, scimGroupB.ID); err != nil {
		t.Fatalf("syncNotifGroupRemove (B): %v", err)
	}
	_, found = findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if found {
		t.Error("user should have been removed after last SCIM group mapping removed")
	}
}

func TestNotifSync_GroupDelete_NoRemoval(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "notif-del-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	// Add membership via SCIM.
	if err := db.AddGroupMemberSCIMManaged(ctx, notifGroup.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddGroupMemberSCIMManaged: %v", err)
	}

	// Add user to SCIM group, then delete SCIM group (CASCADE deletes scim_group_members).
	if err := db.AddSCIMGroupMember(ctx, scimGroup.ID, user.ID, org.ID); err != nil {
		t.Fatalf("setup: AddSCIMGroupMember: %v", err)
	}
	if err := db.DeleteSCIMGroup(ctx, org.ID, scimGroup.ID); err != nil {
		t.Fatalf("DeleteSCIMGroup: %v", err)
	}

	// Notification group membership should still exist.
	_, found := findGroupMember(t, db, ctx, org.ID, notifGroup.ID, user.ID)
	if !found {
		t.Error("notification group membership should survive SCIM group deletion")
	}
}

func TestNotifSync_SoftDeletedTargetGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	org := db.MustCreateOrg(t, ctx, "notif-soft-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
	if err := db.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("setup: %v", err)
	}

	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "Alerts", "Alert group")
	scimGroup, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Engineering")
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup: %v", err)
	}

	// Soft-delete the notification group.
	if err := db.SoftDeleteGroup(ctx, org.ID, notifGroup.ID); err != nil {
		t.Fatalf("SoftDeleteGroup: %v", err)
	}

	// syncNotifGroupAdd should be a no-op — no error, no row created.
	if err := srv.syncNotifGroupAdd(ctx, org.ID, user.ID, notifGroup.ID, scimGroup.ID); err != nil {
		t.Fatalf("syncNotifGroupAdd: %v", err)
	}

	// The group is soft-deleted, so ListGroupMembers may not find it through
	// the normal org-scoped path. Query directly to verify no membership was created.
	// We use ListGroupMembers which joins group_members regardless of the group's deleted_at.
	members, err := db.ListGroupMembers(ctx, org.ID, notifGroup.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	for _, m := range members {
		if m.UserID == user.ID {
			t.Error("no membership should be created for a soft-deleted notification group")
		}
	}
}
