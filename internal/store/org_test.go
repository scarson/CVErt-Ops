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

	newbie, _ := s.CreateUser(ctx, "newbie@example.com", "Newbie", "", 0)
	if err := s.AcceptOrgInvitation(ctx, org.ID, newbie.ID, "member", inv.ID); err != nil {
		t.Fatalf("AcceptOrgInvitation: %v", err)
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

func TestBootstrapFirstUserOrg_OnlyUser(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create a single user.
	user, err := s.CreateUser(ctx, "sole@example.com", "Sole User", "", 0)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Bootstrap should create an org since this is the only user.
	org, err := s.BootstrapFirstUserOrg(ctx, user.ID, "Sole User's Organization")
	if err != nil {
		t.Fatalf("BootstrapFirstUserOrg: %v", err)
	}
	if org == nil {
		t.Fatal("BootstrapFirstUserOrg returned nil for sole user")
	}
	if org.Name != "Sole User's Organization" {
		t.Errorf("org.Name = %q, want %q", org.Name, "Sole User's Organization")
	}

	// Verify user is owner.
	role, err := s.GetOrgMemberRole(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberRole: %v", err)
	}
	if role == nil || *role != "owner" {
		t.Errorf("role = %v, want owner", role)
	}
}

func TestBootstrapFirstUserOrg_MultipleUsers(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two users.
	_, err := s.CreateUser(ctx, "first@example.com", "First", "", 0)
	if err != nil {
		t.Fatalf("CreateUser(first): %v", err)
	}
	second, err := s.CreateUser(ctx, "second@example.com", "Second", "", 0)
	if err != nil {
		t.Fatalf("CreateUser(second): %v", err)
	}

	// Bootstrap should NOT create an org since there are multiple users.
	org, err := s.BootstrapFirstUserOrg(ctx, second.ID, "Should Not Exist")
	if err != nil {
		t.Fatalf("BootstrapFirstUserOrg: %v", err)
	}
	if org != nil {
		t.Errorf("BootstrapFirstUserOrg should return nil for non-first user, got org %v", org.ID)
	}
}

func TestCreateOrgMember_Duplicate(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "DupMemberOrg")
	user, _ := s.CreateUser(ctx, "dupmember@example.com", "DupMember", "", 0)
	if err := s.CreateOrgMember(ctx, org.ID, user.ID, "member"); err != nil {
		t.Fatalf("CreateOrgMember (first): %v", err)
	}

	// Adding the same user again should fail (unique constraint on org_id + user_id).
	err := s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	if err == nil {
		t.Error("expected error on duplicate org member, got nil")
	}
}

func TestAcceptOrgInvitation_Flow(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "AcceptInvOrg")
	admin, _ := s.CreateUser(ctx, "acceptinv-admin@example.com", "Admin", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, admin.ID, "admin")

	token := "accept-flow-token"
	inv, err := s.CreateOrgInvitation(ctx, org.ID, "joiner@example.com", "member", token, admin.ID, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatalf("CreateOrgInvitation: %v", err)
	}

	// Create the joining user.
	joiner, _ := s.CreateUser(ctx, "joiner@example.com", "Joiner", "", 0)

	// AcceptOrgInvitation atomically creates member + marks invitation accepted.
	if err := s.AcceptOrgInvitation(ctx, org.ID, joiner.ID, "member", inv.ID); err != nil {
		t.Fatalf("AcceptOrgInvitation: %v", err)
	}

	// Verify user is now a member.
	role, err := s.GetOrgMemberRole(ctx, org.ID, joiner.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberRole: %v", err)
	}
	if role == nil || *role != "member" {
		t.Errorf("role = %v, want member", role)
	}

	// Verify invitation is marked accepted.
	inv2, _ := s.GetInvitationByToken(ctx, token)
	if !inv2.AcceptedAt.Valid {
		t.Error("AcceptedAt should be set after AcceptOrgInvitation")
	}
}

func TestGetOrgOwnerCount(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "OwnerCountOrg")
	user1, _ := s.CreateUser(ctx, "owner1@example.com", "Owner1", "", 0)
	user2, _ := s.CreateUser(ctx, "owner2@example.com", "Owner2", "", 0)
	user3, _ := s.CreateUser(ctx, "member1@example.com", "Member1", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user1.ID, "owner")
	_ = s.CreateOrgMember(ctx, org.ID, user2.ID, "owner")
	_ = s.CreateOrgMember(ctx, org.ID, user3.ID, "member")

	n, err := s.GetOrgOwnerCount(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetOrgOwnerCount: %v", err)
	}
	if n != 2 {
		t.Errorf("GetOrgOwnerCount = %d, want 2", n)
	}
}

func TestCreateOrgWithOwner(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, _ := s.CreateUser(ctx, "withowner@example.com", "WithOwner", "", 0)

	org, err := s.CreateOrgWithOwner(ctx, "OwnerOrg", user.ID)
	if err != nil {
		t.Fatalf("CreateOrgWithOwner: %v", err)
	}
	if org == nil {
		t.Fatal("CreateOrgWithOwner returned nil")
	}
	if org.Name != "OwnerOrg" {
		t.Errorf("org.Name = %q, want OwnerOrg", org.Name)
	}

	// Verify user is owner.
	role, err := s.GetOrgMemberRole(ctx, org.ID, user.ID)
	if err != nil {
		t.Fatalf("GetOrgMemberRole: %v", err)
	}
	if role == nil || *role != "owner" {
		t.Errorf("role = %v, want owner", role)
	}
}

func TestUpdateOrg(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "OldName")

	updated, err := s.UpdateOrg(ctx, org.ID, "NewName")
	if err != nil {
		t.Fatalf("UpdateOrg: %v", err)
	}
	if updated == nil {
		t.Fatal("UpdateOrg returned nil")
	}
	if updated.Name != "NewName" {
		t.Errorf("Name = %q, want NewName", updated.Name)
	}
}

func TestUpdateOrg_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	updated, err := s.UpdateOrg(ctx, uuid.New(), "X")
	if err != nil {
		t.Fatalf("UpdateOrg(not found): %v", err)
	}
	if updated != nil {
		t.Error("UpdateOrg should return nil for non-existent org")
	}
}

func TestCancelInvitation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "CancelInvOrg")
	admin, _ := s.CreateUser(ctx, "cancelinv-admin@example.com", "CancelAdmin", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, admin.ID, "admin")

	inv, err := s.CreateOrgInvitation(ctx, org.ID, "cancel@example.com", "member", "cancel-tok", admin.ID, time.Now().Add(48*time.Hour))
	if err != nil {
		t.Fatalf("CreateOrgInvitation: %v", err)
	}

	deleted, err := s.CancelInvitation(ctx, org.ID, inv.ID)
	if err != nil {
		t.Fatalf("CancelInvitation: %v", err)
	}
	if !deleted {
		t.Fatal("CancelInvitation: expected row to be deleted")
	}

	// After cancellation, the invitation should no longer be findable.
	got, err := s.GetInvitationByToken(ctx, "cancel-tok")
	if err != nil {
		t.Fatalf("GetInvitationByToken: %v", err)
	}
	if got != nil {
		t.Error("cancelled invitation should not be findable")
	}
}

func TestGetInvitationByToken_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	got, err := s.GetInvitationByToken(ctx, "nonexistent-token")
	if err != nil {
		t.Fatalf("GetInvitationByToken: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for non-existent token, got %+v", got)
	}
}

func TestListUserOrgs_NoOrgs(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	user, _ := s.CreateUser(ctx, "noorgs@example.com", "NoOrgs", "", 0)

	orgs, err := s.ListUserOrgs(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListUserOrgs: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("ListUserOrgs = %d orgs, want 0", len(orgs))
	}
}
