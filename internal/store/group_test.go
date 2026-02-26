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

	org, _ := s.CreateOrg(ctx, "GroupOrg1")

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
	org2, _ := s.CreateOrg(ctx, "GroupOrg1b")
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

	org, _ := s.CreateOrg(ctx, "GroupOrg2")

	// Create group named "X" and soft-delete it.
	grp, _ := s.CreateGroup(ctx, org.ID, "X", "")
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

	org, _ := s.CreateOrg(ctx, "GroupOrg3")
	grp, _ := s.CreateGroup(ctx, org.ID, "Deleted Team", "")

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

	org, _ := s.CreateOrg(ctx, "GroupOrg4")
	grp, _ := s.CreateGroup(ctx, org.ID, "Idempotent Team", "")
	user, _ := s.CreateUser(ctx, "grpuser4@example.com", "GrpUser4", "", 0)

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

	org1, _ := s.CreateOrg(ctx, "GroupOrg5a")
	org2, _ := s.CreateOrg(ctx, "GroupOrg5b")

	grp1, _ := s.CreateGroup(ctx, org1.ID, "Team A", "")
	grp2, _ := s.CreateGroup(ctx, org2.ID, "Team B", "")

	user1, _ := s.CreateUser(ctx, "gmember1@example.com", "GMember1", "", 0)
	user2, _ := s.CreateUser(ctx, "gmember2@example.com", "GMember2", "", 0)

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
