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
	if err := s.q.CreateOrgMember(ctx, generated.CreateOrgMemberParams{
		OrgID:  orgID,
		UserID: userID,
		Role:   role,
	}); err != nil {
		return fmt.Errorf("create org member: %w", err)
	}
	return nil
}

// GetOrgMemberRole returns the role of userID in orgID, or (nil, nil) if not a member.
func (s *Store) GetOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID) (*string, error) {
	role, err := s.q.GetOrgMemberRole(ctx, generated.GetOrgMemberRoleParams{
		OrgID:  orgID,
		UserID: userID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get org member role: %w", err)
	}
	return &role, nil
}

// ListOrgMembers returns all members of an org ordered by join time.
func (s *Store) ListOrgMembers(ctx context.Context, orgID uuid.UUID) ([]generated.ListOrgMembersRow, error) {
	rows, err := s.q.ListOrgMembers(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list org members: %w", err)
	}
	return rows, nil
}

// UpdateOrgMemberRole changes the role of userID in orgID.
func (s *Store) UpdateOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	if err := s.q.UpdateOrgMemberRole(ctx, generated.UpdateOrgMemberRoleParams{
		OrgID:  orgID,
		UserID: userID,
		Role:   role,
	}); err != nil {
		return fmt.Errorf("update org member role: %w", err)
	}
	return nil
}

// RemoveOrgMember removes userID from orgID.
func (s *Store) RemoveOrgMember(ctx context.Context, orgID, userID uuid.UUID) error {
	if err := s.q.DeleteOrgMember(ctx, generated.DeleteOrgMemberParams{
		OrgID:  orgID,
		UserID: userID,
	}); err != nil {
		return fmt.Errorf("remove org member: %w", err)
	}
	return nil
}

// ListUserOrgs returns all orgs a user belongs to, ordered by org name.
func (s *Store) ListUserOrgs(ctx context.Context, userID uuid.UUID) ([]generated.ListUserOrgsRow, error) {
	rows, err := s.q.ListUserOrgs(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user orgs: %w", err)
	}
	return rows, nil
}

// GetOrgOwnerCount returns the number of owners in the given org.
// Used to prevent removing the last owner.
func (s *Store) GetOrgOwnerCount(ctx context.Context, orgID uuid.UUID) (int64, error) {
	n, err := s.q.GetOrgOwnerCount(ctx, orgID)
	if err != nil {
		return 0, fmt.Errorf("get org owner count: %w", err)
	}
	return n, nil
}

// CreateOrgInvitation inserts an invitation record.
func (s *Store) CreateOrgInvitation(ctx context.Context, orgID uuid.UUID, email, role, token string, createdBy uuid.UUID, expiresAt time.Time) error {
	if err := s.q.CreateOrgInvitation(ctx, generated.CreateOrgInvitationParams{
		OrgID:     orgID,
		Email:     email,
		Role:      role,
		Token:     token,
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
	}); err != nil {
		return fmt.Errorf("create org invitation: %w", err)
	}
	return nil
}

// GetInvitationByToken returns the invitation for the given token, or (nil, nil) if not found.
// Callers are responsible for checking expiry and accepted_at.
func (s *Store) GetInvitationByToken(ctx context.Context, token string) (*generated.OrgInvitation, error) {
	row, err := s.q.GetInvitationByToken(ctx, token)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get invitation by token: %w", err)
	}
	return &row, nil
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
	rows, err := s.q.ListOrgInvitations(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list org invitations: %w", err)
	}
	return rows, nil
}

// CancelInvitation deletes an invitation by ID within an org.
func (s *Store) CancelInvitation(ctx context.Context, orgID, id uuid.UUID) error {
	if err := s.q.DeleteOrgInvitation(ctx, generated.DeleteOrgInvitationParams{
		OrgID: orgID,
		ID:    id,
	}); err != nil {
		return fmt.Errorf("cancel invitation: %w", err)
	}
	return nil
}
