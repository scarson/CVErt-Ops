// ABOUTME: Integration tests for SCIM role recomputation from group mappings.
// ABOUTME: Uses real Postgres via testutil.NewTestDB to exercise the full store path.
package api

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/scarson/cvert-ops/internal/config"
	"github.com/scarson/cvert-ops/internal/testutil"
)

// newSCIMTestServer creates a minimal *Server with only the store populated.
// Sufficient for testing recomputeSCIMRole and notification group sync.
func newSCIMTestServer(t *testing.T, db *testutil.TestDB) *Server {
	t.Helper()
	cfg := &config.Config{ //nolint:exhaustruct // test: only relevant fields set
		Argon2MaxConcurrent: 1,
	}
	srv, err := NewServer(db.Store, cfg, ServerDeps{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

// scimRoleSetup creates an org, SSO connection, SCIM config, and an org member
// with the given role. Returns the org ID and user ID.
func scimRoleSetup(t *testing.T, db *testutil.TestDB, ctx context.Context, role string) (orgID, userID uuid.UUID) {
	t.Helper()

	org := db.MustCreateOrg(t, ctx, "scimrole-"+uuid.New().String()[:8])
	user := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "TestUser", "hash", 1)

	if err := db.CreateOrgMember(ctx, org.ID, user.ID, role); err != nil {
		t.Fatalf("setup: CreateOrgMember: %v", err)
	}

	return org.ID, user.ID
}

// setupSCIMGroupWithMapping creates a SCIM group with a mapped role and adds the user.
func setupSCIMGroupWithMapping(t *testing.T, db *testutil.TestDB, ctx context.Context, orgID, userID uuid.UUID, groupName string, mappedRole *string) uuid.UUID {
	t.Helper()

	group, err := db.CreateSCIMGroup(ctx, orgID, nil, groupName)
	if err != nil {
		t.Fatalf("setup: CreateSCIMGroup(%q): %v", groupName, err)
	}

	if mappedRole != nil {
		if err := db.UpdateSCIMGroupMapping(ctx, orgID, group.ID, mappedRole, nil); err != nil {
			t.Fatalf("setup: UpdateSCIMGroupMapping: %v", err)
		}
	}

	if err := db.AddSCIMGroupMember(ctx, group.ID, userID, orgID); err != nil {
		t.Fatalf("setup: AddSCIMGroupMember: %v", err)
	}

	return group.ID
}

func TestRoleRecompute_SingleGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "viewer")
	adminRole := "admin"
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Admins", &adminRole)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "admin" {
		t.Errorf("role = %q, want %q", member.Role, "admin")
	}
}

func TestRoleRecompute_MultipleGroups_HighestWins(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "viewer")

	memberRole := "member"
	adminRole := "admin"
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Members", &memberRole)
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Admins", &adminRole)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "admin" {
		t.Errorf("role = %q, want %q (highest mapped role)", member.Role, "admin")
	}
}

func TestRoleRecompute_NoMappedGroups(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "admin")

	// Group with no mapped_role (NULL).
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "NoMapping", nil)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "viewer" {
		t.Errorf("role = %q, want %q (default_role fallback)", member.Role, "viewer")
	}
}

func TestRoleRecompute_NeverSetsOwner(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "viewer")

	// Even if someone mapped a group to admin (highest SCIM-assignable role),
	// owner should never be assigned by SCIM.
	adminRole := "admin"
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Admins", &adminRole)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role == "owner" {
		t.Error("SCIM role recomputation must never assign owner role")
	}
}

func TestRoleRecompute_SCIMExempt_Skipped(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "viewer")

	// Mark user as SCIM-exempt.
	if err := db.UpdateOrgMemberSCIMExempt(ctx, orgID, userID, true); err != nil {
		t.Fatalf("setup: UpdateOrgMemberSCIMExempt: %v", err)
	}

	adminRole := "admin"
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Admins", &adminRole)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "viewer" {
		t.Errorf("role = %q, want %q (SCIM-exempt user should not be modified)", member.Role, "viewer")
	}
}

func TestRoleRecompute_OwnerNotDowngraded(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "owner")

	viewerRole := "viewer"
	setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Viewers", &viewerRole)

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "owner" {
		t.Errorf("role = %q, want %q (owner must not be downgraded by SCIM)", member.Role, "owner")
	}
}

func TestRoleRecompute_RemovedFromAllGroups(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()
	srv := newSCIMTestServer(t, db)

	orgID, userID := scimRoleSetup(t, db, ctx, "admin")

	// Add to a group with mapped role, then remove.
	adminRole := "admin"
	groupID := setupSCIMGroupWithMapping(t, db, ctx, orgID, userID, "Admins", &adminRole)
	if err := db.RemoveSCIMGroupMember(ctx, orgID, groupID, userID); err != nil {
		t.Fatalf("RemoveSCIMGroupMember: %v", err)
	}

	if err := srv.recomputeSCIMRole(ctx, orgID, userID, "viewer"); err != nil {
		t.Fatalf("recomputeSCIMRole: %v", err)
	}

	member, err := db.GetOrgMemberFull(ctx, orgID, userID)
	if err != nil {
		t.Fatalf("GetOrgMemberFull: %v", err)
	}
	if member.Role != "viewer" {
		t.Errorf("role = %q, want %q (should fall back to defaultRole)", member.Role, "viewer")
	}
}
