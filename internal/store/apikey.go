// ABOUTME: Store methods for API key lifecycle management.
// ABOUTME: LookupAPIKey is the authentication hot-path; does not take orgID.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateAPIKey inserts a new API key record. keyHash is sha256(raw_key).
// expiresAt may be sql.NullTime{} for a never-expiring key.
func (s *Store) CreateAPIKey(ctx context.Context, orgID, createdBy uuid.UUID, keyHash, name, role string, expiresAt sql.NullTime) (*generated.ApiKey, error) {
	row, err := s.q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{
		OrgID:           orgID,
		CreatedByUserID: createdBy,
		KeyHash:         keyHash,
		Name:            name,
		Role:            role,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("create api key: %w", err)
	}
	return &row, nil
}

// LookupAPIKey returns the active (non-revoked, non-expired) key matching keyHash,
// or (nil, nil) if not found. Caller is responsible for validating org membership.
// Executes with RLS bypass because no org context exists during the auth hot-path.
func (s *Store) LookupAPIKey(ctx context.Context, keyHash string) (*generated.ApiKey, error) {
	var result *generated.ApiKey
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.LookupAPIKey(ctx, keyHash)
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
		return nil, fmt.Errorf("lookup api key: %w", err)
	}
	return result, nil
}

// ListOrgAPIKeys returns all API keys for an org ordered by creation time descending.
// key_hash is excluded from the result — never expose raw hashes to the API layer.
func (s *Store) ListOrgAPIKeys(ctx context.Context, orgID uuid.UUID) ([]generated.ListOrgAPIKeysRow, error) {
	rows, err := s.q.ListOrgAPIKeys(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("list org api keys: %w", err)
	}
	return rows, nil
}

// RevokeAPIKey marks the key as revoked. A wrong orgID is silently a no-op.
func (s *Store) RevokeAPIKey(ctx context.Context, orgID, id uuid.UUID) error {
	if err := s.q.RevokeAPIKey(ctx, generated.RevokeAPIKeyParams{
		OrgID: orgID,
		ID:    id,
	}); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	return nil
}

// UpdateAPIKeyLastUsed records the current time as last_used_at for the key.
// Executes with RLS bypass — called from async goroutines without an org context.
func (s *Store) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpdateAPIKeyLastUsed(ctx, id)
	})
}
