// ABOUTME: Store methods for group and group membership management.
// ABOUTME: All methods are org-scoped; soft-delete preserves data for audit trails.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateGroup inserts a new group for the given org. Returns the created group.
func (s *Store) CreateGroup(ctx context.Context, orgID uuid.UUID, name, description string) (*generated.Group, error) {
	var row generated.Group
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateGroup(ctx, generated.CreateGroupParams{
			OrgID:       orgID,
			Name:        name,
			Description: description,
		})
		if err != nil {
			return fmt.Errorf("create group: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// GetGroup returns the group with the given id within orgID, or (nil, nil) if not
// found or soft-deleted.
func (s *Store) GetGroup(ctx context.Context, orgID, id uuid.UUID) (*generated.Group, error) {
	var result *generated.Group
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetGroup(ctx, generated.GetGroupParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get group: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// ListOrgGroups returns all non-deleted groups for an org ordered by name.
func (s *Store) ListOrgGroups(ctx context.Context, orgID uuid.UUID) ([]generated.Group, error) {
	var rows []generated.Group
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListOrgGroups(ctx, orgID)
		if err != nil {
			return fmt.Errorf("list org groups: %w", err)
		}
		return nil
	})
	return rows, err
}

// UpdateGroup updates the name and description of a group within orgID.
func (s *Store) UpdateGroup(ctx context.Context, orgID, id uuid.UUID, name, description string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.UpdateGroup(ctx, generated.UpdateGroupParams{
			ID:          id,
			OrgID:       orgID,
			Name:        name,
			Description: description,
		}); err != nil {
			return fmt.Errorf("update group: %w", err)
		}
		return nil
	})
}

// SoftDeleteGroup marks the group as deleted. Members are preserved in the database.
func (s *Store) SoftDeleteGroup(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.SoftDeleteGroup(ctx, generated.SoftDeleteGroupParams{
			ID:    id,
			OrgID: orgID,
		}); err != nil {
			return fmt.Errorf("soft delete group: %w", err)
		}
		return nil
	})
}

// AddGroupMember adds userID to the group. Idempotent — duplicate adds are silently ignored.
func (s *Store) AddGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.AddGroupMember(ctx, generated.AddGroupMemberParams{
			OrgID:   orgID,
			GroupID: groupID,
			UserID:  userID,
		}); err != nil {
			return fmt.Errorf("add group member: %w", err)
		}
		return nil
	})
}

// RemoveGroupMember removes userID from groupID within orgID.
func (s *Store) RemoveGroupMember(ctx context.Context, orgID, groupID, userID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.RemoveGroupMember(ctx, generated.RemoveGroupMemberParams{
			GroupID: groupID,
			UserID:  userID,
			OrgID:   orgID,
		}); err != nil {
			return fmt.Errorf("remove group member: %w", err)
		}
		return nil
	})
}

// ListGroupMembers returns all members of groupID within orgID, ordered by display name.
func (s *Store) ListGroupMembers(ctx context.Context, orgID, groupID uuid.UUID) ([]generated.ListGroupMembersRow, error) {
	var rows []generated.ListGroupMembersRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListGroupMembers(ctx, generated.ListGroupMembersParams{
			GroupID: groupID,
			OrgID:   orgID,
		})
		if err != nil {
			return fmt.Errorf("list group members: %w", err)
		}
		return nil
	})
	return rows, err
}
