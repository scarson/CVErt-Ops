// ABOUTME: Store methods for organization, membership, and invitation management.
// ABOUTME: All org-scoped methods take orgID as Layer 1 tenant isolation.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateOrg inserts a new organization row. Returns the created org.
func (s *Store) CreateOrg(ctx context.Context, name string) (*generated.Organization, error) {
	row, err := s.q.CreateOrg(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("create org: %w", err)
	}
	return &row, nil
}

// UpdateOrg updates the org name. Returns (nil, nil) if the org is not found or soft-deleted.
func (s *Store) UpdateOrg(ctx context.Context, id uuid.UUID, name string) (*generated.Organization, error) {
	row, err := s.q.UpdateOrg(ctx, generated.UpdateOrgParams{ID: id, Name: name})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update org: %w", err)
	}
	return &row, nil
}

// CreateOrgWithOwner atomically creates a new org and adds ownerID as owner.
// Uses RLS bypass since no org context exists at creation time.
func (s *Store) CreateOrgWithOwner(ctx context.Context, name string, ownerID uuid.UUID) (*generated.Organization, error) {
	var org generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		created, err := q.CreateOrg(ctx, name)
		if err != nil {
			return fmt.Errorf("create org: %w", err)
		}
		org = created
		return q.CreateOrgMember(ctx, generated.CreateOrgMemberParams{
			OrgID:  org.ID,
			UserID: ownerID,
			Role:   "owner",
		})
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// GetOrgByID returns the org with the given ID, or (nil, nil) if not found or soft-deleted.
func (s *Store) GetOrgByID(ctx context.Context, id uuid.UUID) (*generated.Organization, error) {
	row, err := s.q.GetOrgByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get org by id: %w", err)
	}
	return &row, nil
}

// CreateOrgMember adds a user to an org with the given role.
func (s *Store) CreateOrgMember(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.CreateOrgMember(ctx, generated.CreateOrgMemberParams{
			OrgID:  orgID,
			UserID: userID,
			Role:   role,
		}); err != nil {
			return fmt.Errorf("create org member: %w", err)
		}
		return nil
	})
}

// GetOrgMemberRole returns the role of userID in orgID, or (nil, nil) if not a member.
// Executes with RLS bypass — called from RequireOrgRole middleware before org context is set.
func (s *Store) GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (*string, error) {
	var result *string
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		role, err := q.GetOrgMemberRole(ctx, generated.GetOrgMemberRoleParams{
			OrgID:  orgID,
			UserID: userID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		result = &role
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get org member role: %w", err)
	}
	return result, nil
}

// ListOrgMembers returns all members of an org ordered by join time.
func (s *Store) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]generated.ListOrgMembersRow, error) {
	var rows []generated.ListOrgMembersRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListOrgMembers(ctx, orgID)
		if err != nil {
			return fmt.Errorf("list org members: %w", err)
		}
		return nil
	})
	return rows, err
}

// UpdateOrgMemberRole changes the role of userID in orgID.
func (s *Store) UpdateOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.UpdateOrgMemberRole(ctx, generated.UpdateOrgMemberRoleParams{
			OrgID:  orgID,
			UserID: userID,
			Role:   role,
		}); err != nil {
			return fmt.Errorf("update org member role: %w", err)
		}
		return nil
	})
}

// RemoveOrgMember removes userID from orgID.
func (s *Store) RemoveOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.DeleteOrgMember(ctx, generated.DeleteOrgMemberParams{
			OrgID:  orgID,
			UserID: userID,
		}); err != nil {
			return fmt.Errorf("remove org member: %w", err)
		}
		return nil
	})
}

// ListUserOrgs returns all orgs a user belongs to, ordered by org name.
// Uses RLS bypass — this is a cross-org query; no single orgID context applies.
func (s *Store) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]generated.ListUserOrgsRow, error) {
	var rows []generated.ListUserOrgsRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListUserOrgs(ctx, userID)
		if err != nil {
			return fmt.Errorf("list user orgs: %w", err)
		}
		return nil
	})
	return rows, err
}

// GetOrgOwnerCount returns the number of owners in the given org.
// Used to prevent removing the last owner.
func (s *Store) GetOrgOwnerCount(ctx context.Context, orgID uuid.UUID) (int64, error) {
	var n int64
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		n, err = q.GetOrgOwnerCount(ctx, orgID)
		if err != nil {
			return fmt.Errorf("get org owner count: %w", err)
		}
		return nil
	})
	return n, err
}

// CreateOrgInvitation inserts an invitation record and returns it.
func (s *Store) CreateOrgInvitation(ctx context.Context, orgID uuid.UUID, email, role, token string, createdBy uuid.UUID, expiresAt time.Time) (*generated.OrgInvitation, error) {
	var row generated.OrgInvitation
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateOrgInvitation(ctx, generated.CreateOrgInvitationParams{
			OrgID:     orgID,
			Email:     email,
			Role:      role,
			Token:     token,
			CreatedBy: createdBy,
			ExpiresAt: expiresAt,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create org invitation: %w", err)
	}
	return &row, nil
}

// GetInvitationByToken returns the invitation for the given token, or (nil, nil) if not found.
// Uses RLS bypass — called from public and accept endpoints with no org context.
// Callers are responsible for checking expiry and accepted_at.
func (s *Store) GetInvitationByToken(ctx context.Context, token string) (*generated.OrgInvitation, error) {
	var row generated.OrgInvitation
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.GetInvitationByToken(ctx, token)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get invitation by token: %w", err)
	}
	return &row, nil
}

// AcceptOrgInvitation atomically creates an org_members row and marks the invitation accepted.
// Uses RLS bypass since the caller has no org context yet (they are joining the org).
func (s *Store) AcceptOrgInvitation(ctx context.Context, orgID, userID uuid.UUID, role string, invitationID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.CreateOrgMember(ctx, generated.CreateOrgMemberParams{
			OrgID:  orgID,
			UserID: userID,
			Role:   role,
		}); err != nil {
			return fmt.Errorf("create org member: %w", err)
		}
		return q.AcceptInvitation(ctx, invitationID)
	})
}

// AcceptInvitation marks the invitation as accepted by setting accepted_at = now().
func (s *Store) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	if err := s.q.AcceptInvitation(ctx, id); err != nil {
		return fmt.Errorf("accept invitation: %w", err)
	}
	return nil
}

// ListOrgInvitations returns all pending, unexpired invitations for an org.
func (s *Store) ListOrgInvitations(ctx context.Context, orgID uuid.UUID) ([]generated.OrgInvitation, error) {
	var rows []generated.OrgInvitation
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		rows, err = q.ListOrgInvitations(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list org invitations: %w", err)
	}
	return rows, nil
}

// CancelInvitation deletes an invitation by ID within an org.
func (s *Store) CancelInvitation(ctx context.Context, orgID, id uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		if err := q.DeleteOrgInvitation(ctx, generated.DeleteOrgInvitationParams{
			OrgID: orgID,
			ID:    id,
		}); err != nil {
			return fmt.Errorf("cancel invitation: %w", err)
		}
		return nil
	})
}
