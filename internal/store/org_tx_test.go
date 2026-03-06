// ABOUTME: Integration tests for OrgTx and WorkerTx helpers in store/store.go.
// ABOUTME: Verifies SET LOCAL app.org_id enforcement and RLS fail-closed guarantee.
package store_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/scarson/cvert-ops/internal/testutil"
)

// TestOrgTx_SetsOrgID verifies that OrgTx sets app.org_id for the duration of
// the transaction and that RLS applies (org_members for other org are invisible).
// Uses AppStore (cvert_ops_app, NOBYPASSRLS) to enforce RLS policies.
func TestOrgTx_SetsOrgID(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs and one member each using the superuser store (bypasses RLS).
	org1, _ := s.CreateOrg(ctx, "RLSOrg1a")
	org2, _ := s.CreateOrg(ctx, "RLSOrg1b")
	user1, _ := s.CreateUser(ctx, "rlsuser1a@example.com", "RLSUser1a", "", 0)
	user2, _ := s.CreateUser(ctx, "rlsuser1b@example.com", "RLSUser1b", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user1.ID, "member")
	_ = s.CreateOrgMember(ctx, org2.ID, user2.ID, "member")

	// Open OrgTx for org1 using the app-role store — RLS is enforced.
	var visibleCount int
	err := s.AppStore.OrgTx(ctx, org1.ID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&visibleCount)
	})
	if err != nil {
		t.Fatalf("OrgTx: %v", err)
	}
	// With app.org_id = org1.ID, only org1's member is visible.
	if visibleCount != 1 {
		t.Errorf("OrgTx: visible members = %d, want 1 (RLS should filter org2's member)", visibleCount)
	}
}

// TestOrgTx_FailClosed verifies that a raw query with NO app.org_id set returns
// 0 rows — not an error. This is the RLS fail-closed guarantee.
// CRITICAL: if this test fails, the dual-layer isolation is broken.
func TestOrgTx_FailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Insert an org + member using the superuser store (bypasses RLS for setup).
	org, _ := s.CreateOrg(ctx, "RLSOrg2")
	user, _ := s.CreateUser(ctx, "rlsuser2@example.com", "RLSUser2", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "owner")

	// Acquire a raw connection from the app-role pool with no SET LOCAL app.org_id.
	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	// Query org_members with no org context — must return 0 rows (fail-closed).
	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 rows with no app.org_id, got %d — RLS isolation broken", count)
	}
}

// TestWorkerTx_BypassRLS verifies that WorkerTx with app.bypass_rls = 'on'
// can read rows from all orgs. Uses AppStore to confirm the bypass is effective
// for non-superuser connections.
func TestWorkerTx_BypassRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	// Create two orgs with one member each using superuser store.
	org1, _ := s.CreateOrg(ctx, "RLSOrg3a")
	org2, _ := s.CreateOrg(ctx, "RLSOrg3b")
	user1, _ := s.CreateUser(ctx, "rlsuser3a@example.com", "RLSUser3a", "", 0)
	user2, _ := s.CreateUser(ctx, "rlsuser3b@example.com", "RLSUser3b", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user1.ID, "member")
	_ = s.CreateOrgMember(ctx, org2.ID, user2.ID, "member")

	// WorkerTx on the app-role store sets bypass_rls = 'on' — should see all rows.
	var count int
	err := s.AppStore.WorkerTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT COUNT(*) FROM org_members").Scan(&count)
	})
	if err != nil {
		t.Fatalf("WorkerTx: %v", err)
	}
	if count != 2 {
		t.Errorf("WorkerTx bypass: visible members = %d, want 2 (should see both orgs)", count)
	}
}

// TestListOrgMembers_AppStoreRLS verifies that ListOrgMembers returns the correct
// rows when called via AppStore (NOBYPASSRLS). Without withOrgTx, no app.org_id
// is set, so RLS filters all rows and the result is empty.
func TestListOrgMembers_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "RLSOrg4")
	user, _ := s.CreateUser(ctx, "rlsuser4@example.com", "RLSUser4", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "member")

	members, err := s.AppStore.ListOrgMembers(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgMembers: %v", err)
	}
	if len(members) != 1 {
		t.Errorf("ListOrgMembers: got %d members, want 1 — RLS not enforcing org context", len(members))
	}
}

// TestCreateGroup_AppStoreRLS verifies that CreateGroup succeeds when called
// via AppStore. Without withOrgTx, the INSERT's WITH CHECK clause fails because
// app.org_id is not set, returning an RLS policy violation error.
func TestCreateGroup_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "RLSOrg5")

	group, err := s.AppStore.CreateGroup(ctx, org.ID, "alpha", "")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if group == nil {
		t.Fatal("CreateGroup: returned nil group, want non-nil")
	}
}

// TestCreateAPIKey_AppStoreRLS verifies that CreateAPIKey succeeds when called
// via AppStore. Without withOrgTx, the INSERT's WITH CHECK clause fails because
// app.org_id is not set.
func TestCreateAPIKey_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "RLSOrg6")
	user, _ := s.CreateUser(ctx, "rlsuser6@example.com", "RLSUser6", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "member")

	key, err := s.AppStore.CreateAPIKey(ctx, org.ID, user.ID, "testhash6", "test-key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key == nil {
		t.Fatal("CreateAPIKey: returned nil key, want non-nil")
	}
}

// ── org_invitations RLS tests ─────────────────────────────────────────────────

// TestCancelInvitation_AppStoreRLS verifies that CancelInvitation succeeds when
// called via AppStore. This requires GRANT DELETE on org_invitations (the migration
// originally only granted SELECT, INSERT, UPDATE) and withOrgTx wrapping.
func TestCancelInvitation_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InvRLS1")
	user, _ := s.CreateUser(ctx, "invrlsuser1@example.com", "InvRLSUser1", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	inv, err := s.CreateOrgInvitation(ctx, org.ID, "cancel-target@example.com", "member", "invrlstoken1", user.ID, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	// CancelInvitation via AppStore must succeed — tests GRANT DELETE + withOrgTx.
	if err := s.AppStore.CancelInvitation(ctx, org.ID, inv.ID); err != nil {
		t.Fatalf("CancelInvitation via AppStore: %v — missing DELETE grant or withOrgTx", err)
	}
}

// TestInvitation_RLSFailClosed verifies that a raw query on AppStore with no
// app.org_id set returns 0 invitation rows — the RLS fail-closed guarantee.
// CRITICAL: if this fails, cross-org invitation data is exposed.
func TestInvitation_RLSFailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InvRLS2")
	user, _ := s.CreateUser(ctx, "invrlsuser2@example.com", "InvRLSUser2", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	if _, err := s.CreateOrgInvitation(ctx, org.ID, "rls-target@example.com", "member", "invrlstoken2", user.ID, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	// Raw query on AppStore connection — no SET LOCAL app.org_id, must return 0 rows.
	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM org_invitations").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 invitation rows with no app.org_id, got %d — RLS missing", count)
	}
}

// TestGetInvitationByToken_AppStoreBypass verifies that GetInvitationByToken
// succeeds via AppStore even without an org context. The store method must use
// withBypassTx so the public token-lookup path works after RLS is enabled.
func TestGetInvitationByToken_AppStoreBypass(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InvRLS3")
	user, _ := s.CreateUser(ctx, "invrlsuser3@example.com", "InvRLSUser3", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	const token = "publicinvtoken3"
	if _, err := s.CreateOrgInvitation(ctx, org.ID, "public-lookup@example.com", "viewer", token, user.ID, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	// GetInvitationByToken via AppStore must find the invitation with no org context.
	inv, err := s.AppStore.GetInvitationByToken(ctx, token)
	if err != nil {
		t.Fatalf("GetInvitationByToken: %v", err)
	}
	if inv == nil {
		t.Fatal("GetInvitationByToken: returned nil — withBypassTx not set, RLS blocking public lookup")
	}
}

// TestCreateInvitation_AppStoreRLS verifies that CreateOrgInvitation succeeds
// via AppStore. With RLS enabled, the INSERT's WITH CHECK clause requires app.org_id
// to be set — withOrgTx must wrap the call.
func TestCreateInvitation_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InvRLS4")
	user, _ := s.CreateUser(ctx, "invrlsuser4@example.com", "InvRLSUser4", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")

	inv, err := s.AppStore.CreateOrgInvitation(ctx, org.ID, "new-invite@example.com", "member", "invrlstoken4", user.ID, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("CreateOrgInvitation via AppStore: %v", err)
	}
	if inv == nil {
		t.Fatal("CreateOrgInvitation via AppStore: returned nil")
	}
}

// TestListInvitations_AppStoreRLS verifies that ListOrgInvitations returns the
// correct rows via AppStore. With RLS enabled, the SELECT's USING clause requires
// app.org_id to be set — withOrgTx must wrap the call.
func TestListInvitations_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "InvRLS5")
	user, _ := s.CreateUser(ctx, "invrlsuser5@example.com", "InvRLSUser5", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	if _, err := s.CreateOrgInvitation(ctx, org.ID, "list-target@example.com", "member", "invrlstoken5", user.ID, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("create invitation: %v", err)
	}

	invs, err := s.AppStore.ListOrgInvitations(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgInvitations via AppStore: %v", err)
	}
	if len(invs) != 1 {
		t.Errorf("ListOrgInvitations: got %d invitations, want 1 — withOrgTx not set", len(invs))
	}
}

// ── api_keys RLS fail-closed tests ────────────────────────────────────────────

// TestAPIKey_RLSFailClosed verifies that a raw query on AppStore with no
// app.org_id set returns 0 api_keys rows — the RLS fail-closed guarantee.
// CRITICAL: if this fails, API keys from other orgs could be exposed.
func TestAPIKey_RLSFailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "APIKeyRLS1")
	user, _ := s.CreateUser(ctx, "apikeyrlsuser@example.com", "APIKeyRLSUser", "", 0)
	_ = s.CreateOrgMember(ctx, org.ID, user.ID, "admin")
	_, err := s.CreateAPIKey(ctx, org.ID, user.ID, "apikeyrlshash1", "rls-key", "member", sql.NullTime{})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}

	// Raw query on AppStore connection — no SET LOCAL app.org_id, must return 0 rows.
	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM api_keys").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 api_keys rows with no app.org_id, got %d — RLS missing", count)
	}
}

// TestListOrgAPIKeys_AppStoreRLS verifies that ListOrgAPIKeys via AppStore
// returns only keys for the specified org (RLS enforced via withOrgTx).
func TestListOrgAPIKeys_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "APIKeyRLS2a")
	org2, _ := s.CreateOrg(ctx, "APIKeyRLS2b")
	user, _ := s.CreateUser(ctx, "apikeyrlsuser2@example.com", "APIKeyRLSUser2", "", 0)
	_ = s.CreateOrgMember(ctx, org1.ID, user.ID, "admin")
	_ = s.CreateOrgMember(ctx, org2.ID, user.ID, "admin")
	_, _ = s.CreateAPIKey(ctx, org1.ID, user.ID, "rlskeyhash2a", "org1-key", "member", sql.NullTime{})
	_, _ = s.CreateAPIKey(ctx, org2.ID, user.ID, "rlskeyhash2b", "org2-key", "member", sql.NullTime{})

	keys, err := s.AppStore.ListOrgAPIKeys(ctx, org1.ID)
	if err != nil {
		t.Fatalf("ListOrgAPIKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key for org1, got %d", len(keys))
	}
	if keys[0].Name != "org1-key" {
		t.Errorf("Name = %q, want org1-key", keys[0].Name)
	}
}

// ── groups RLS fail-closed tests ──────────────────────────────────────────────

// TestGroup_RLSFailClosed verifies that a raw query on AppStore with no
// app.org_id set returns 0 groups rows — the RLS fail-closed guarantee.
// CRITICAL: if this fails, groups from other orgs could be exposed.
func TestGroup_RLSFailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "GroupRLS1")
	_, err := s.CreateGroup(ctx, org.ID, "rls-group", "")
	if err != nil {
		t.Fatalf("create group: %v", err)
	}

	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM groups").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 groups rows with no app.org_id, got %d — RLS missing", count)
	}
}

// TestListOrgGroups_AppStoreRLS verifies that ListOrgGroups via AppStore
// returns only groups for the specified org.
func TestListOrgGroups_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "GroupRLS2a")
	org2, _ := s.CreateOrg(ctx, "GroupRLS2b")
	_, _ = s.CreateGroup(ctx, org1.ID, "org1-group", "")
	_, _ = s.CreateGroup(ctx, org2.ID, "org2-group", "")

	groups, err := s.AppStore.ListOrgGroups(ctx, org1.ID)
	if err != nil {
		t.Fatalf("ListOrgGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for org1, got %d", len(groups))
	}
	if groups[0].Name != "org1-group" {
		t.Errorf("Name = %q, want org1-group", groups[0].Name)
	}
}

// ── group_members RLS fail-closed tests ───────────────────────────────────────

// TestGroupMember_RLSFailClosed verifies that a raw query on AppStore with no
// app.org_id set returns 0 group_members rows — the RLS fail-closed guarantee.
// CRITICAL: group_members has denormalized org_id with its own RLS policy.
func TestGroupMember_RLSFailClosed(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org, _ := s.CreateOrg(ctx, "GMemberRLS1")
	grp, _ := s.CreateGroup(ctx, org.ID, "rls-gm-group", "")
	user, _ := s.CreateUser(ctx, "gmrlsuser@example.com", "GMRLSUser", "", 0)
	_ = s.AddGroupMember(ctx, org.ID, grp.ID, user.ID)

	conn, err := s.AppStore.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire app pool conn: %v", err)
	}
	defer conn.Release()

	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM group_members").Scan(&count); err != nil {
		t.Fatalf("fail-closed query: %v", err)
	}
	if count != 0 {
		t.Errorf("fail-closed: expected 0 group_members rows with no app.org_id, got %d — RLS missing", count)
	}
}

// TestListGroupMembers_AppStoreRLS verifies that ListGroupMembers via AppStore
// returns only members for the correct org (RLS enforced via withOrgTx).
func TestListGroupMembers_AppStoreRLS(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org1, _ := s.CreateOrg(ctx, "GMemberRLS2a")
	org2, _ := s.CreateOrg(ctx, "GMemberRLS2b")
	grp1, _ := s.CreateGroup(ctx, org1.ID, "team-a", "")
	grp2, _ := s.CreateGroup(ctx, org2.ID, "team-b", "")
	user1, _ := s.CreateUser(ctx, "gmrlsuser2a@example.com", "GMRLSUser2a", "", 0)
	user2, _ := s.CreateUser(ctx, "gmrlsuser2b@example.com", "GMRLSUser2b", "", 0)
	_ = s.AddGroupMember(ctx, org1.ID, grp1.ID, user1.ID)
	_ = s.AddGroupMember(ctx, org2.ID, grp2.ID, user2.ID)

	members, err := s.AppStore.ListGroupMembers(ctx, org1.ID, grp1.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member for org1 group, got %d", len(members))
	}
	if members[0].UserID != user1.ID {
		t.Errorf("unexpected member: got %v, want %v", members[0].UserID, user1.ID)
	}
}
