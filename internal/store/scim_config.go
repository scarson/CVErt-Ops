// ABOUTME: Store methods for SCIM provisioning config CRUD.
// ABOUTME: Token hash lookup uses withBypassTx (pre-org-context auth). All other methods use withOrgTx.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// SCIMConfigRow is the SCIM config record returned by store methods.
type SCIMConfigRow = generated.ScimConfig

// CreateSCIMConfig inserts a new SCIM config for an org.
// Returns error if org already has a config (UNIQUE constraint on org_id).
func (s *Store) CreateSCIMConfig(ctx context.Context, orgID, ssoConnID uuid.UUID, enabled bool, tokenHash, tokenPrefix, defaultRole string) (*SCIMConfigRow, error) {
	var row SCIMConfigRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateSCIMConfig(ctx, generated.CreateSCIMConfigParams{
			OrgID:           orgID,
			SsoConnectionID: ssoConnID,
			Enabled:         enabled,
			TokenHash:       tokenHash,
			TokenPrefix:     tokenPrefix,
			DefaultRole:     defaultRole,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create scim config: %w", err)
	}
	return &row, nil
}

// GetSCIMConfig returns the SCIM config for the given org, or (nil, nil) if none exists.
func (s *Store) GetSCIMConfig(ctx context.Context, orgID uuid.UUID) (*SCIMConfigRow, error) {
	var result *SCIMConfigRow
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetSCIMConfigByOrgID(ctx, orgID)
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
		return nil, fmt.Errorf("get scim config: %w", err)
	}
	return result, nil
}

// LookupSCIMConfigByTokenHash finds a SCIM config by bearer token hash.
// Uses bypass RLS — called from SCIM auth middleware before org context is established.
// Returns (nil, nil) if not found.
func (s *Store) LookupSCIMConfigByTokenHash(ctx context.Context, tokenHash string) (*SCIMConfigRow, error) {
	var result *SCIMConfigRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetSCIMConfigByTokenHash(ctx, tokenHash)
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
		return nil, fmt.Errorf("lookup scim config by token hash: %w", err)
	}
	return result, nil
}

// LookupSCIMConfigBySSOConnectionID finds a SCIM config by SSO connection ID.
// Uses bypass RLS — for auth-path lookups.
// Returns (nil, nil) if not found.
func (s *Store) LookupSCIMConfigBySSOConnectionID(ctx context.Context, ssoConnID uuid.UUID) (*SCIMConfigRow, error) {
	var result *SCIMConfigRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetSCIMConfigBySSOConnectionID(ctx, ssoConnID)
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
		return nil, fmt.Errorf("lookup scim config by sso connection: %w", err)
	}
	return result, nil
}

// UpdateSCIMConfig updates the enabled flag and default role for an org's SCIM config.
func (s *Store) UpdateSCIMConfig(ctx context.Context, orgID uuid.UUID, enabled bool, defaultRole string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateSCIMConfig(ctx, generated.UpdateSCIMConfigParams{
			OrgID:       orgID,
			Enabled:     enabled,
			DefaultRole: defaultRole,
		})
	})
}

// RotateSCIMToken replaces the token hash and prefix for an org's SCIM config.
func (s *Store) RotateSCIMToken(ctx context.Context, orgID uuid.UUID, tokenHash, tokenPrefix string) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.UpdateSCIMConfigToken(ctx, generated.UpdateSCIMConfigTokenParams{
			OrgID:       orgID,
			TokenHash:   tokenHash,
			TokenPrefix: tokenPrefix,
		})
	})
}

// DeleteSCIMConfig removes the org's SCIM config.
func (s *Store) DeleteSCIMConfig(ctx context.Context, orgID uuid.UUID) error {
	return s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.DeleteSCIMConfig(ctx, orgID)
	})
}
