// ABOUTME: Integration tests for store/group.go — group and group_member CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateAndGetGroup(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg1")

	grp, err := s.CreateGroup(ctx, org.ID, "Alpha Team", "First team")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if grp.Name != "Alpha Team" {
		t.Errorf("Name = %q, want %q", grp.Name, "Alpha Team")
	}

	got, err := s.GetGroup(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got == nil {
		t.Fatal("GetGroup returned nil for existing group")
	}
	if got.ID != grp.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, grp.ID)
	}

	// GetGroup with wrong org returns nil.
	org2 := s.MustCreateOrg(t, ctx, "GroupOrg1b")
	missing, err := s.GetGroup(ctx, org2.ID, grp.ID)
	if err != nil {
		t.Fatalf("GetGroup(wrong org): %v", err)
	}
	if missing != nil {
		t.Error("GetGroup with wrong org should return nil")
	}
}

func TestSoftDeleteGroup_NameReuseAllowed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg2")

	// Create group named "X" and soft-delete it.
	grp := s.MustCreateGroup(t, ctx, org.ID, "X", "")
	if err := s.SoftDeleteGroup(ctx, org.ID, grp.ID); err != nil {
		t.Fatalf("SoftDeleteGroup: %v", err)
	}

	// Create another group with the same name — partial unique index allows reuse.
	grp2, err := s.CreateGroup(ctx, org.ID, "X", "")
	if err != nil {
		t.Fatalf("CreateGroup (name reuse after delete): %v", err)
	}
	if grp2.ID == grp.ID {
		t.Error("expected new group with different ID")
	}
}

func TestGetGroup_DeletedReturnsNil(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg3")
	grp := s.MustCreateGroup(t, ctx, org.ID, "Deleted Team", "")

	if err := s.SoftDeleteGroup(ctx, org.ID, grp.ID); err != nil {
		t.Fatalf("SoftDeleteGroup: %v", err)
	}

	got, err := s.GetGroup(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("GetGroup(deleted): %v", err)
	}
	if got != nil {
		t.Error("GetGroup should return nil for soft-deleted group")
	}
}

func TestAddGroupMember_Idempotent(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg4")
	grp := s.MustCreateGroup(t, ctx, org.ID, "Idempotent Team", "")
	user := s.MustCreateUser(t, ctx, "grpuser4@example.com", "GrpUser4", "", 0)

	// Add user twice — second should be a no-op (ON CONFLICT DO NOTHING).
	if err := s.AddGroupMember(ctx, org.ID, grp.ID, user.ID); err != nil {
		t.Fatalf("AddGroupMember (first): %v", err)
	}
	if err := s.AddGroupMember(ctx, org.ID, grp.ID, user.ID); err != nil {
		t.Fatalf("AddGroupMember (duplicate): %v", err)
	}

	members, err := s.ListGroupMembers(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("expected 1 member after duplicate add, got %d", len(members))
	}
}

func TestListGroupMembers_OrgScoped(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1 := s.MustCreateOrg(t, ctx, "GroupOrg5a")
	org2 := s.MustCreateOrg(t, ctx, "GroupOrg5b")

	grp1 := s.MustCreateGroup(t, ctx, org1.ID, "Team A", "")
	grp2 := s.MustCreateGroup(t, ctx, org2.ID, "Team B", "")

	user1 := s.MustCreateUser(t, ctx, "gmember1@example.com", "GMember1", "", 0)
	user2 := s.MustCreateUser(t, ctx, "gmember2@example.com", "GMember2", "", 0)

	_ = s.AddGroupMember(ctx, org1.ID, grp1.ID, user1.ID)
	_ = s.AddGroupMember(ctx, org2.ID, grp2.ID, user2.ID)

	members, err := s.ListGroupMembers(ctx, org1.ID, grp1.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member for grp1, got %d", len(members))
	}
	if members[0].UserID != user1.ID {
		t.Errorf("unexpected member: got %v, want %v", members[0].UserID, user1.ID)
	}
}

func TestRemoveGroupMember(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg6")
	grp := s.MustCreateGroup(t, ctx, org.ID, "RemoveTeam", "")
	user := s.MustCreateUser(t, ctx, "grpremove@example.com", "GrpRemove", "", 0)

	_ = s.AddGroupMember(ctx, org.ID, grp.ID, user.ID)

	if err := s.RemoveGroupMember(ctx, org.ID, grp.ID, user.ID); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}

	members, err := s.ListGroupMembers(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members after remove, got %d", len(members))
	}
}

func TestRemoveGroupMember_NonExistentIsNoOp(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg7")
	grp := s.MustCreateGroup(t, ctx, org.ID, "NoopRemove", "")
	user := s.MustCreateUser(t, ctx, "grpnoopremove@example.com", "GrpNoopRemove", "", 0)

	// Removing a user who was never added should not error.
	if err := s.RemoveGroupMember(ctx, org.ID, grp.ID, user.ID); err != nil {
		t.Fatalf("RemoveGroupMember (non-existent): %v", err)
	}
}

func TestListGroupMembers_EmptyGroup(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg8")
	grp := s.MustCreateGroup(t, ctx, org.ID, "Empty Team", "")

	members, err := s.ListGroupMembers(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers (empty): %v", err)
	}
	if len(members) != 0 {
		t.Errorf("expected 0 members in empty group, got %d", len(members))
	}
}

func TestUpdateGroup(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg9")
	grp := s.MustCreateGroup(t, ctx, org.ID, "OriginalTeam", "old desc")

	if err := s.UpdateGroup(ctx, org.ID, grp.ID, "RenamedTeam", "new desc"); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}

	got, err := s.GetGroup(ctx, org.ID, grp.ID)
	if err != nil {
		t.Fatalf("GetGroup: %v", err)
	}
	if got == nil {
		t.Fatal("GetGroup returned nil after update")
	}
	if got.Name != "RenamedTeam" {
		t.Errorf("Name = %q, want RenamedTeam", got.Name)
	}
	if got.Description != "new desc" {
		t.Errorf("Description = %q, want 'new desc'", got.Description)
	}
}

func TestListOrgGroups(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg10")
	if _, err := s.CreateGroup(ctx, org.ID, "Beta Team", ""); err != nil {
		t.Fatalf("setup: CreateGroup: %v", err)
	}
	if _, err := s.CreateGroup(ctx, org.ID, "Alpha Team", ""); err != nil {
		t.Fatalf("setup: CreateGroup: %v", err)
	}

	groups, err := s.ListOrgGroups(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgGroups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("ListOrgGroups = %d groups, want 2", len(groups))
	}
	// ListOrgGroups orders by name ASC.
	if groups[0].Name != "Alpha Team" || groups[1].Name != "Beta Team" {
		t.Errorf("unexpected order: %q, %q", groups[0].Name, groups[1].Name)
	}
}

func TestListOrgGroups_Empty(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg11")

	groups, err := s.ListOrgGroups(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgGroups (empty): %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("ListOrgGroups on empty org = %d groups, want 0", len(groups))
	}
}

func TestListOrgGroups_ExcludesDeleted(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "GroupOrg12")
	grp1 := s.MustCreateGroup(t, ctx, org.ID, "Active Team", "")
	grp2 := s.MustCreateGroup(t, ctx, org.ID, "Deleted Team", "")
	_ = s.SoftDeleteGroup(ctx, org.ID, grp2.ID)

	groups, err := s.ListOrgGroups(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("ListOrgGroups = %d groups, want 1 (soft-deleted excluded)", len(groups))
	}
	if groups[0].ID != grp1.ID {
		t.Errorf("expected active group %v, got %v", grp1.ID, groups[0].ID)
	}
}
