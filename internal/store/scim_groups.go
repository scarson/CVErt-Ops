// ABOUTME: Store methods for SCIM group and membership CRUD operations.
// ABOUTME: All methods use withOrgTx for dual-layer tenant isolation (orgID param + RLS).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateSCIMGroup inserts a new SCIM group for the given org. Returns the created row.
func (s *Store) CreateSCIMGroup(ctx context.Context, orgID uuid.UUID, externalID *string, displayName string) (*generated.ScimGroup, error) {
	var extID sql.NullString
	if externalID != nil {
		extID = sql.NullString{String: *externalID, Valid: true}
	}

	var row generated.ScimGroup
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateSCIMGroup(ctx, generated.CreateSCIMGroupParams{
			OrgID:       orgID,
			ExternalID:  extID,
			DisplayName: displayName,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create scim group: %w", err)
	}
	return &row, nil
}

// GetSCIMGroup returns the SCIM group by ID within the given org, or (nil, nil) if not found.
func (s *Store) GetSCIMGroup(ctx context.Context, orgID uuid.UUID, id uuid.UUID) (*generated.ScimGroup, error) {
	var result *generated.ScimGroup
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSCIMGroupByID(ctx, generated.GetSCIMGroupByIDParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get scim group: %w", err)
	}
	return result, nil
}

// GetSCIMGroupByExternalID returns the SCIM group matching (org_id, external_id),
// or (nil, nil) if not found.
func (s *Store) GetSCIMGroupByExternalID(ctx context.Context, orgID uuid.UUID, externalID string) (*generated.ScimGroup, error) {
	var result *generated.ScimGroup
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSCIMGroupByExternalID(ctx, generated.GetSCIMGroupByExternalIDParams{
			OrgID:      orgID,
			ExternalID: sql.NullString{String: externalID, Valid: true},
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get scim group by external id: %w", err)
	}
	return result, nil
}

// GetSCIMGroupByDisplayName returns the SCIM group matching (org_id, display_name),
// or (nil, nil) if not found.
func (s *Store) GetSCIMGroupByDisplayName(ctx context.Context, orgID uuid.UUID, displayName string) (*generated.ScimGroup, error) {
	var result *generated.ScimGroup
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSCIMGroupByDisplayName(ctx, generated.GetSCIMGroupByDisplayNameParams{
			OrgID:       orgID,
			DisplayName: displayName,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &row
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get scim group by display name: %w", err)
	}
	return result, nil
}

// ListSCIMGroups returns all SCIM groups for the org with member counts,
// ordered by display_name.
func (s *Store) ListSCIMGroups(ctx context.Context, orgID uuid.UUID) ([]generated.ListSCIMGroupsRow, error) {
	var rows []generated.ListSCIMGroupsRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListSCIMGroups(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list scim groups: %w", err)
	}
	return rows, err
}

// UpdateSCIMGroup updates the display name and external ID of a SCIM group.
func (s *Store) UpdateSCIMGroup(ctx context.Context, orgID uuid.UUID, id uuid.UUID, displayName string, externalID *string) error {
	var extID sql.NullString
	if externalID != nil {
		extID = sql.NullString{String: *externalID, Valid: true}
	}

	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateSCIMGroup(ctx, generated.UpdateSCIMGroupParams{
			ID:          id,
			DisplayName: displayName,
			ExternalID:  extID,
			OrgID:       orgID,
		})
	})
}

// UpdateSCIMGroupMapping updates the mapped role and notification group for a SCIM group.
func (s *Store) UpdateSCIMGroupMapping(ctx context.Context, orgID uuid.UUID, id uuid.UUID, mappedRole *string, mappedGroupID *uuid.UUID) error {
	var role sql.NullString
	if mappedRole != nil {
		role = sql.NullString{String: *mappedRole, Valid: true}
	}
	var groupID uuid.NullUUID
	if mappedGroupID != nil {
		groupID = uuid.NullUUID{UUID: *mappedGroupID, Valid: true}
	}

	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateSCIMGroupMapping(ctx, generated.UpdateSCIMGroupMappingParams{
			ID:            id,
			MappedRole:    role,
			MappedGroupID: groupID,
			OrgID:         orgID,
		})
	})
}

// DeleteSCIMGroup deletes a SCIM group by ID. Members are cascade-deleted.
func (s *Store) DeleteSCIMGroup(ctx context.Context, orgID uuid.UUID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.DeleteSCIMGroup(ctx, generated.DeleteSCIMGroupParams{
			ID:    id,
			OrgID: orgID,
		})
	})
}

// AddSCIMGroupMember adds a user to a SCIM group. Idempotent — duplicate adds are ignored.
func (s *Store) AddSCIMGroupMember(ctx context.Context, scimGroupID, userID, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.AddSCIMGroupMember(ctx, generated.AddSCIMGroupMemberParams{
			ScimGroupID: scimGroupID,
			UserID:      userID,
			OrgID:       orgID,
		})
	})
}

// RemoveSCIMGroupMember removes a user from a SCIM group.
func (s *Store) RemoveSCIMGroupMember(ctx context.Context, orgID uuid.UUID, scimGroupID, userID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.RemoveSCIMGroupMember(ctx, generated.RemoveSCIMGroupMemberParams{
			ScimGroupID: scimGroupID,
			UserID:      userID,
			OrgID:       orgID,
		})
	})
}

// ListSCIMGroupMembers returns all user IDs in the given SCIM group.
func (s *Store) ListSCIMGroupMembers(ctx context.Context, orgID uuid.UUID, scimGroupID uuid.UUID) ([]uuid.UUID, error) {
	var result []uuid.UUID
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListSCIMGroupMembers(ctx, generated.ListSCIMGroupMembersParams{
			ScimGroupID: scimGroupID,
			OrgID:       orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list scim group members: %w", err)
	}
	return result, nil
}

// ListUserSCIMGroups returns all SCIM groups that the given user belongs to within the org.
func (s *Store) ListUserSCIMGroups(ctx context.Context, userID, orgID uuid.UUID) ([]generated.ScimGroup, error) {
	var rows []generated.ScimGroup
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListUserSCIMGroups(ctx, generated.ListUserSCIMGroupsParams{
			UserID: userID,
			OrgID:  orgID,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list user scim groups: %w", err)
	}
	return rows, err
}

// CountOtherSCIMGroupsWithSameMapping counts how many other SCIM groups (excluding
// excludeGroupID) map to the same notification group and contain the given user.
func (s *Store) CountOtherSCIMGroupsWithSameMapping(ctx context.Context, orgID uuid.UUID, userID uuid.UUID, mappedGroupID uuid.UUID, excludeGroupID uuid.UUID) (int, error) {
	var count int32
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		count, err = q.CountOtherSCIMGroupsWithSameMapping(ctx, generated.CountOtherSCIMGroupsWithSameMappingParams{
			UserID:        userID,
			MappedGroupID: uuid.NullUUID{UUID: mappedGroupID, Valid: true},
			ID:            excludeGroupID,
			OrgID:         orgID,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count other scim groups with same mapping: %w", err)
	}
	return int(count), nil
}
