// ABOUTME: Notification group sync from SCIM group mappings.
// ABOUTME: Propagates SCIM group membership changes to notification groups.
package api

import (
	"context"

	"github.com/google/uuid"
)

// syncNotifGroupAdd adds a user to a notification group as a SCIM-managed member.
// If the notification group is soft-deleted, this is a no-op. If the user is already
// a member (manually or via SCIM), the existing membership is preserved via ON CONFLICT DO NOTHING.
func (srv *Server) syncNotifGroupAdd(ctx context.Context, orgID, userID, mappedGroupID, _ uuid.UUID) error {
	// Verify the target notification group exists and is not soft-deleted.
	group, err := srv.store.GetGroupIfActive(ctx, mappedGroupID)
	if err != nil {
		return err
	}
	if group == nil {
		return nil // soft-deleted or non-existent — no-op
	}

	return srv.store.AddGroupMemberSCIMManaged(ctx, mappedGroupID, userID, orgID)
}

// syncNotifGroupRemove removes a user from a notification group, but only if:
//   - The membership is scim_managed=true (manual memberships are preserved)
//   - No other SCIM group with the same mapped_group_id still includes the user
func (srv *Server) syncNotifGroupRemove(ctx context.Context, _, userID, mappedGroupID, scimGroupID uuid.UUID) error {
	// Check if another SCIM group maps to the same notification group and includes this user.
	count, err := srv.store.CountOtherSCIMGroupsWithSameMapping(ctx, userID, mappedGroupID, scimGroupID)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // another SCIM group still maps here — keep the membership
	}

	return srv.store.RemoveSCIMManagedGroupMember(ctx, mappedGroupID, userID)
}
