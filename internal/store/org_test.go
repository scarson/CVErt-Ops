// ABOUTME: Integration tests for store/org.go — org, member, and invitation CRUD.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateAndGetOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, err := s.CreateOrg(ctx, "Acme Corp")
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if org.Name != "Acme Corp" {
		t.Errorf("org.Name = %q, want %q", org.Name, "Acme Corp")
	}

	got, err := s.GetOrgByID(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrgByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetOrgByID returned nil for existing org")
	}
	if got.ID != org.ID {
		t.Errorf("ID mismatch: got %v, want %v", got.ID, org.ID)
	}

	// GetOrgByID for non-existent ID returns nil.
	missing, err := s.GetOrgByID(ctx, uuid.New())
	if err != nil {
		t.Fatalf("GetOrgByID(missing): %v", err)
	}
	if missing != nil {
		t.Error("GetOrgByID(missing) should return nil")
	}
}

func TestGetOrgMemberRole_NonMember(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "OrgA")
	user, _ := s.CreateUser(ctx, "alice@example.com", "Alice", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "member")

	// Different user — not a member.
	stranger, _ := s.CreateUser(ctx, "stranger@example.com", "Stranger", "", 0)
	role, err := s.GetOrgMemberRole(ctx, org.ID, stranger.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberRole: %v", err)
	}
	if role != nil {
		t.Errorf("expected nil for non-member, got %q", *role)
	}
}

func TestGetOrgMemberRole_Member(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "OrgB")
	user, _ := s.CreateUser(ctx, "bob@example.com", "Bob", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	role, err := s.GetOrgMemberRole(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberRole: %v", err)
	}
	if role == nil {
		t.Fatal("GetOrgMemberRole returned nil for existing member")
	}
	if *role != "admin" {
		t.Errorf("role = %q, want %q", *role, "admin")
	}
}

func TestListOrgMembers_OnlyShowsOwnOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "Org1")
	org2, _ := s.CreateOrg(ctx, "Org2")
	user1, _ := s.CreateUser(ctx, "u1@example.com", "U1", "", 0)
	user2, _ := s.CreateUser(ctx, "u2@example.com", "U2", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user1.ID, "owner")
	_ = s.CreateOrgMember(ctx, org2.ID, user2.ID, "owner")

	members, err := s.ListOrgMembers(ctx, org1.ID)
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("ListOrgMembers returned %d members, want 1", len(members))
	}
	if members[0].UserID != user1.ID {
		t.Errorf("unexpected member: got %v, want %v", members[0].UserID, user1.ID)
	}
}

func TestListUserOrgs_MultipleOrgs(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs — ListUserOrgs orders by org name, so use alpha-sortable names.
	orgA, _ := s.CreateOrg(ctx, "Alpha Corp")
	orgB, _ := s.CreateOrg(ctx, "Beta Corp")
	user, _ := s.CreateUser(ctx, "carol@example.com", "Carol", "", 0)
	_ = s.CreateOrgMember(ctx, orgA.ID, user.ID, "member")
	_ = s.CreateOrgMember(ctx, orgB.ID, user.ID, "admin")

	orgs, err := s.ListUserOrgs(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserOrgs: %v", err)
	}
	if len(orgs) != 2 {
		t.Fatalf("ListUserOrgs returned %d orgs, want 2", len(orgs))
	}
	// Ordered by name: Alpha first, Beta second.
	if orgs[0].Name != "Alpha Corp" || orgs[1].Name != "Beta Corp" {
		t.Errorf("unexpected order: %v, %v", orgs[0].Name, orgs[1].Name)
	}
	if orgs[0].Role != "member" || orgs[1].Role != "admin" {
		t.Errorf("unexpected roles: %v, %v", orgs[0].Role, orgs[1].Role)
	}
}

func TestUpdateAndRemoveOrgMember(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "ChangeOrg")
	user, _ := s.CreateUser(ctx, "dave2@example.com", "Dave", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "viewer")

	// Promote to admin.
	if err := s.UpdateOrgMemberRole(ctx, org.ID, user.ID, "admin"); err != nil {
		t.Fatalf("UpdateOrgMemberRole: %v", err)
	}
	role, _ := s.GetOrgMemberRole(ctx, org.ID, user.ID)
	if *role != "admin" {
		t.Errorf("role after update = %q, want admin", *role)
	}

	// Remove member.
	if err := s.RemoveOrgMember(ctx, org.ID, user.ID); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}
	gone, _ := s.GetOrgMemberRole(ctx, org.ID, user.ID)
	if gone != nil {
		t.Error("member should be gone after RemoveOrgMember")
	}
}

func TestCreateOrgInvitation_AcceptFlow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InviteOrg")
	admin, _ := s.CreateUser(ctx, "admin@example.com", "Admin", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, admin.ID, "admin")

	token := "abc123token"
	expires := time.Now().Add(48 * time.Hour)
	_, err := s.CreateOrgInvitation(ctx, org.ID, "newbie@example.com", "member", token, admin.ID, expires)
	if err != nil {
		t.Fatalf("CreateOrgInvitation: %v", err)
	}

	inv, err := s.GetInvitationByToken(ctx, token)
	if err != nil {
		t.Fatalf("GetInvitationByToken: %v", err)
	}
	if inv == nil {
		t.Fatal("GetInvitationByToken returned nil for existing token")
	}
	if inv.Email != "newbie@example.com" {
		t.Errorf("email = %q, want newbie@example.com", inv.Email)
	}
	if inv.AcceptedAt.Valid {
		t.Error("AcceptedAt should be null before acceptance")
	}

	if err := s.AcceptInvitation(ctx, inv.ID); err != nil {
		t.Fatalf("AcceptInvitation: %v", err)
	}
	inv2, _ := s.GetInvitationByToken(ctx, token)
	if !inv2.AcceptedAt.Valid {
		t.Error("AcceptedAt should be set after acceptance")
	}
}

func TestListOrgInvitations_ExpiryFiltering(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "FilterOrg")
	admin, _ := s.CreateUser(ctx, "admin2@example.com", "Admin2", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, admin.ID, "admin")

	// Active invitation.
	_, _ = s.CreateOrgInvitation(ctx, org.ID, "active@example.com", "member",
		"activetoken", admin.ID, time.Now().Add(48*time.Hour))

	// Expired invitation (expires in the past).
	_, _ = s.CreateOrgInvitation(ctx, org.ID, "expired@example.com", "member",
		"expiredtoken", admin.ID, time.Now().Add(-1*time.Hour))

	list, err := s.ListOrgInvitations(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgInvitations: %v", err)
	}
	// Only the active invitation should appear.
	if len(list) != 1 {
		t.Fatalf("ListOrgInvitations returned %d items, want 1", len(list))
	}
	if list[0].Email != "active@example.com" {
		t.Errorf("unexpected invitation email: %q", list[0].Email)
	}

	// GetInvitationByToken still returns expired tokens (expiry checked at handler level).
	expired, err := s.GetInvitationByToken(ctx, "expiredtoken")
	if err != nil {
		t.Fatalf("GetInvitationByToken(expired): %v", err)
	}
	if expired == nil {
		t.Error("GetInvitationByToken should return expired invitation (handler checks expiry)")
	}
}
