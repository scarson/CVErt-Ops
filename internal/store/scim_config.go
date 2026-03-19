// ABOUTME: Store methods for SCIM provisioning config CRUD.
// ABOUTME: Token lookup uses withBypassTx (pre-org-context in SCIM auth middleware).
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

// LookupSCIMConfigByTokenHash finds a SCIM config by bearer token hash.
// Uses withBypassTx — called from SCIM auth middleware (pre-org-context).
// Returns (nil, nil) if no config matches.
func (s *Store) LookupSCIMConfigByTokenHash(ctx context.Context, tokenHash string) (*SCIMConfigRow, error) {
	var row SCIMConfigRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.GetSCIMConfigByTokenHash(ctx, tokenHash)
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup scim config by token: %w", err)
	}
	return &row, nil
}
