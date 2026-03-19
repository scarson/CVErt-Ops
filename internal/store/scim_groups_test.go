// ABOUTME: Integration tests for SCIM group and membership store methods.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestCreateSCIMGroup(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMGroupOrg")
	extID := "ext-group-1"

	group, err := db.CreateSCIMGroup(ctx, org.ID, &extID, "Engineering")
	require.NoError(t, err)
	require.NotNil(t, group)
	require.Equal(t, org.ID, group.OrgID)
	require.Equal(t, "Engineering", group.DisplayName)
	require.True(t, group.ExternalID.Valid)
	require.Equal(t, "ext-group-1", group.ExternalID.String)
	require.False(t, group.MappedRole.Valid, "mapped_role should be null")
	require.False(t, group.MappedGroupID.Valid, "mapped_group_id should be null")
}

func TestCreateSCIMGroup_DuplicateName(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMDupNameOrg")

	_, err := db.CreateSCIMGroup(ctx, org.ID, nil, "SameName")
	require.NoError(t, err)

	_, err = db.CreateSCIMGroup(ctx, org.ID, nil, "SameName")
	require.Error(t, err, "expected unique constraint error for duplicate (org_id, display_name)")
}

func TestGetSCIMGroupByExternalID(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMExtIDOrg")
	extID := "ext-lookup"

	created, err := db.CreateSCIMGroup(ctx, org.ID, &extID, "LookupGroup")
	require.NoError(t, err)

	// Lookup by external_id.
	got, err := db.GetSCIMGroupByExternalID(ctx, org.ID, "ext-lookup")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, created.ID, got.ID)
	require.Equal(t, "LookupGroup", got.DisplayName)

	// Non-existent external_id → nil, nil.
	got, err = db.GetSCIMGroupByExternalID(ctx, org.ID, "no-such-id")
	require.NoError(t, err)
	require.Nil(t, got)
}

func TestListSCIMGroups_WithMemberCounts(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMListOrg")

	groupA, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Alpha")
	require.NoError(t, err)
	groupB, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Beta")
	require.NoError(t, err)

	// Create 3 users and add them to group A.
	for i := 0; i < 3; i++ {
		u := db.MustCreateUser(t, ctx, uuid.New().String()+"@example.com", "User", "hash", 1)
		require.NoError(t, db.CreateOrgMember(ctx, org.ID, u.ID, "member"))
		require.NoError(t, db.AddSCIMGroupMember(ctx, groupA.ID, u.ID, org.ID))
	}

	rows, err := db.ListSCIMGroups(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	// Sorted by display_name → Alpha first, Beta second.
	require.Equal(t, "Alpha", rows[0].DisplayName)
	require.Equal(t, int32(3), rows[0].MemberCount)
	require.Equal(t, "Beta", rows[1].DisplayName)
	require.Equal(t, groupB.ID, rows[1].ID) // use groupB to avoid unused variable
	require.Equal(t, int32(0), rows[1].MemberCount)
}

func TestUpdateSCIMGroupMapping(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMMappingOrg")

	group, err := db.CreateSCIMGroup(ctx, org.ID, nil, "MapGroup")
	require.NoError(t, err)

	// Create a notification group to map to.
	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "NotifGroup", "for mapping test")

	mappedRole := "admin"
	err = db.UpdateSCIMGroupMapping(ctx, group.ID, &mappedRole, &notifGroup.ID)
	require.NoError(t, err)

	// Re-read and verify.
	got, err := db.GetSCIMGroup(ctx, group.ID)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.True(t, got.MappedRole.Valid)
	require.Equal(t, "admin", got.MappedRole.String)
	require.True(t, got.MappedGroupID.Valid)
	require.Equal(t, notifGroup.ID, got.MappedGroupID.UUID)
}

func TestDeleteSCIMGroup_CascadesMembers(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMDelCascadeOrg")

	group, err := db.CreateSCIMGroup(ctx, org.ID, nil, "CascadeGroup")
	require.NoError(t, err)

	user := db.MustCreateUser(t, ctx, "cascade@example.com", "Cascade", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, user.ID, "member"))
	require.NoError(t, db.AddSCIMGroupMember(ctx, group.ID, user.ID, org.ID))

	// Verify member exists.
	members, err := db.ListSCIMGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	// Delete group.
	require.NoError(t, db.DeleteSCIMGroup(ctx, group.ID))

	// Verify group gone.
	got, err := db.GetSCIMGroup(ctx, group.ID)
	require.NoError(t, err)
	require.Nil(t, got)

	// Verify members cascade-deleted (query the underlying DB directly).
	var count int
	err = db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM scim_group_members WHERE scim_group_id = $1", group.ID).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 0, count, "scim_group_members should be cascade-deleted")
}

func TestAddSCIMGroupMember_Idempotent(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMIdempotentOrg")

	group, err := db.CreateSCIMGroup(ctx, org.ID, nil, "IdempotentGroup")
	require.NoError(t, err)

	user := db.MustCreateUser(t, ctx, "idempotent@example.com", "Idempotent", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	// Add twice — no error.
	require.NoError(t, db.AddSCIMGroupMember(ctx, group.ID, user.ID, org.ID))
	require.NoError(t, db.AddSCIMGroupMember(ctx, group.ID, user.ID, org.ID))

	members, err := db.ListSCIMGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1, "member count should be 1 after duplicate add")
}

func TestRemoveSCIMGroupMember(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMRemoveOrg")

	group, err := db.CreateSCIMGroup(ctx, org.ID, nil, "RemoveGroup")
	require.NoError(t, err)

	user := db.MustCreateUser(t, ctx, "remove@example.com", "Remove", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, user.ID, "member"))
	require.NoError(t, db.AddSCIMGroupMember(ctx, group.ID, user.ID, org.ID))

	// Remove.
	require.NoError(t, db.RemoveSCIMGroupMember(ctx, group.ID, user.ID))

	members, err := db.ListSCIMGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Empty(t, members)
}

func TestListUserSCIMGroups(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMListUserOrg")

	group1, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Group1")
	require.NoError(t, err)
	group2, err := db.CreateSCIMGroup(ctx, org.ID, nil, "Group2")
	require.NoError(t, err)

	user := db.MustCreateUser(t, ctx, "multigroup@example.com", "MultiGroup", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	// Add user to both groups.
	require.NoError(t, db.AddSCIMGroupMember(ctx, group1.ID, user.ID, org.ID))
	require.NoError(t, db.AddSCIMGroupMember(ctx, group2.ID, user.ID, org.ID))

	groups, err := db.ListUserSCIMGroups(ctx, user.ID, org.ID)
	require.NoError(t, err)
	require.Len(t, groups, 2)

	// User not in any groups.
	other := db.MustCreateUser(t, ctx, "nogroup@example.com", "NoGroup", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, other.ID, "member"))
	groups, err = db.ListUserSCIMGroups(ctx, other.ID, org.ID)
	require.NoError(t, err)
	require.Empty(t, groups)
}

func TestCountOtherSCIMGroupsWithSameMapping(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	org := db.MustCreateOrg(t, ctx, "SCIMCountOrg")

	// Create a notification group.
	notifGroup := db.MustCreateGroup(t, ctx, org.ID, "SharedNotifGroup", "shared mapping target")

	groupA, err := db.CreateSCIMGroup(ctx, org.ID, nil, "CountGroupA")
	require.NoError(t, err)
	groupB, err := db.CreateSCIMGroup(ctx, org.ID, nil, "CountGroupB")
	require.NoError(t, err)

	// Map both SCIM groups to the same notification group.
	role := "member"
	require.NoError(t, db.UpdateSCIMGroupMapping(ctx, groupA.ID, &role, &notifGroup.ID))
	require.NoError(t, db.UpdateSCIMGroupMapping(ctx, groupB.ID, &role, &notifGroup.ID))

	user := db.MustCreateUser(t, ctx, "countuser@example.com", "CountUser", "hash", 1)
	require.NoError(t, db.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	// User in both groups.
	require.NoError(t, db.AddSCIMGroupMember(ctx, groupA.ID, user.ID, org.ID))
	require.NoError(t, db.AddSCIMGroupMember(ctx, groupB.ID, user.ID, org.ID))

	// Excluding group A → count should be 1 (group B).
	count, err := db.CountOtherSCIMGroupsWithSameMapping(ctx, user.ID, notifGroup.ID, groupA.ID)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Now remove user from group B.
	require.NoError(t, db.RemoveSCIMGroupMember(ctx, groupB.ID, user.ID))

	// Excluding group A → count should be 0.
	count, err = db.CountOtherSCIMGroupsWithSameMapping(ctx, user.ID, notifGroup.ID, groupA.ID)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestSCIMGroups_RLSIsolation(t *testing.T) {
	t.Parallel()
	db := testutil.NewTestDB(t)
	ctx := context.Background()

	orgA := db.MustCreateOrg(t, ctx, "SCIMRlsOrgA")
	orgB := db.MustCreateOrg(t, ctx, "SCIMRlsOrgB")

	// Create group in org A (via superuser).
	_, err := db.CreateSCIMGroup(ctx, orgA.ID, nil, "OrgAGroup")
	require.NoError(t, err)

	// Query via AppStore scoped to org B → should return zero results.
	groups, err := db.AppStore.ListSCIMGroups(ctx, orgB.ID)
	require.NoError(t, err)
	require.Empty(t, groups, "RLS should isolate org A groups from org B queries")

	// Also verify org A can see its own group via AppStore.
	groups, err = db.AppStore.ListSCIMGroups(ctx, orgA.ID)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "OrgAGroup", groups[0].DisplayName)
}
