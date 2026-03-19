// ABOUTME: Integration tests for org member deactivation, reactivation, and SCIM exempt flag.
// ABOUTME: Uses testutil.NewTestDB; each test runs in its own container (t.Parallel).
package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/scarson/cvert-ops/internal/testutil"
)

func TestDeactivateOrgMember(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "DeactivateOrg")
	user := s.MustCreateUser(t, ctx, "deact@example.com", "Deact", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	require.NoError(t, s.DeactivateOrgMember(ctx, org.ID, user.ID))

	member, err := s.GetOrgMemberFull(ctx, org.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, member)
	require.True(t, member.DeactivatedAt.Valid, "DeactivatedAt should be set")
	require.WithinDuration(t, time.Now(), member.DeactivatedAt.Time, time.Minute,
		"DeactivatedAt should be recent")
}

func TestReactivateOrgMember(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "ReactivateOrg")
	user := s.MustCreateUser(t, ctx, "react@example.com", "React", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	require.NoError(t, s.DeactivateOrgMember(ctx, org.ID, user.ID))
	require.NoError(t, s.ReactivateOrgMember(ctx, org.ID, user.ID))

	member, err := s.GetOrgMemberFull(ctx, org.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, member)
	require.False(t, member.DeactivatedAt.Valid, "DeactivatedAt should be cleared after reactivation")
}

func TestCountActiveOrgMembers(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "CountActiveOrg")
	u1 := s.MustCreateUser(t, ctx, "active1@example.com", "Active1", "", 0)
	u2 := s.MustCreateUser(t, ctx, "active2@example.com", "Active2", "", 0)
	u3 := s.MustCreateUser(t, ctx, "deact3@example.com", "Deact3", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, u1.ID, "member"))
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, u2.ID, "member"))
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, u3.ID, "member"))

	// Deactivate one member.
	require.NoError(t, s.DeactivateOrgMember(ctx, org.ID, u3.ID))

	count, err := s.CountActiveOrgMembers(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 2, count)
}

func TestCountActiveOrgOwners_SoleOwner(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "SoleOwnerOrg")
	owner := s.MustCreateUser(t, ctx, "soleowner@example.com", "SoleOwner", "", 0)
	member := s.MustCreateUser(t, ctx, "normalmember@example.com", "Member", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, owner.ID, "owner"))
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, member.ID, "member"))

	count, err := s.CountActiveOrgOwners(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, count)

	// Deactivate the sole owner.
	require.NoError(t, s.DeactivateOrgMember(ctx, org.ID, owner.ID))

	count, err = s.CountActiveOrgOwners(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 0, count)
}

func TestCountActiveOrgOwners_MultipleOwners(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "MultiOwnerOrg")
	o1 := s.MustCreateUser(t, ctx, "owner1m@example.com", "Owner1", "", 0)
	o2 := s.MustCreateUser(t, ctx, "owner2m@example.com", "Owner2", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, o1.ID, "owner"))
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, o2.ID, "owner"))

	// Deactivate one owner.
	require.NoError(t, s.DeactivateOrgMember(ctx, org.ID, o1.ID))

	count, err := s.CountActiveOrgOwners(ctx, org.ID)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestUpdateOrgMemberSCIMExempt(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "SCIMExemptOrg")
	user := s.MustCreateUser(t, ctx, "scimexempt@example.com", "SCIMExempt", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, org.ID, user.ID, "member"))

	// Set exempt to true.
	require.NoError(t, s.UpdateOrgMemberSCIMExempt(ctx, org.ID, user.ID, true))

	member, err := s.GetOrgMemberFull(ctx, org.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, member)
	require.True(t, member.ScimExempt)

	// Set exempt back to false.
	require.NoError(t, s.UpdateOrgMemberSCIMExempt(ctx, org.ID, user.ID, false))

	member, err = s.GetOrgMemberFull(ctx, org.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, member)
	require.False(t, member.ScimExempt)
}

func TestDeactivation_RLSIsolation(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	orgA := s.MustCreateOrg(t, ctx, "RLS_OrgA")
	orgB := s.MustCreateOrg(t, ctx, "RLS_OrgB")
	user := s.MustCreateUser(t, ctx, "rlsuser@example.com", "RLSUser", "", 0)
	require.NoError(t, s.CreateOrgMember(ctx, orgA.ID, user.ID, "member"))
	require.NoError(t, s.CreateOrgMember(ctx, orgB.ID, user.ID, "member"))

	// Deactivate via org A scope — should work.
	require.NoError(t, s.DeactivateOrgMember(ctx, orgA.ID, user.ID))

	memberA, err := s.GetOrgMemberFull(ctx, orgA.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, memberA)
	require.True(t, memberA.DeactivatedAt.Valid, "member in org A should be deactivated")

	// Try deactivating via org B scope (for the user in org A) — should have no effect.
	// The user is in org B too, but we're checking that org B scoped operation
	// can't affect org A membership.
	require.NoError(t, s.DeactivateOrgMember(ctx, orgB.ID, user.ID))

	// Verify org B membership is now deactivated (that's expected — it's the user's
	// own membership in org B).
	memberB, err := s.GetOrgMemberFull(ctx, orgB.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, memberB)
	require.True(t, memberB.DeactivatedAt.Valid, "member in org B should be deactivated")

	// Now reactivate org A membership and verify org B is still deactivated.
	require.NoError(t, s.ReactivateOrgMember(ctx, orgA.ID, user.ID))

	memberA, err = s.GetOrgMemberFull(ctx, orgA.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, memberA)
	require.False(t, memberA.DeactivatedAt.Valid, "member in org A should be reactivated")

	memberB, err = s.GetOrgMemberFull(ctx, orgB.ID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, memberB)
	require.True(t, memberB.DeactivatedAt.Valid, "member in org B should still be deactivated")
}

func TestGetOrgMemberFull_NotFound(t *testing.T) {
	t.Parallel()
	s := testutil.NewTestDB(t)
	ctx := context.Background()

	org := s.MustCreateOrg(t, ctx, "NotFoundOrg")

	member, err := s.GetOrgMemberFull(ctx, org.ID, uuid.New())
	require.NoError(t, err)
	require.Nil(t, member, "non-existent member should return nil, nil")
}
