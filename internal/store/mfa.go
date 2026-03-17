// ABOUTME: Store methods for MFA credential CRUD operations.
// ABOUTME: All operations use withBypassTx — mfa_credentials is a global table (no RLS).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateMFACredential inserts a new MFA credential for the given user and method.
// secretEnc should be the encrypted TOTP secret (non-nil for TOTP, nil for email_otp).
func (s *Store) CreateMFACredential(ctx context.Context, userID uuid.UUID, method string, secretEnc []byte) (*generated.MfaCredential, error) {
	var row generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateMFACredential(ctx, generated.CreateMFACredentialParams{
			UserID:    userID,
			Method:    method,
			SecretEnc: secretEnc,
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create mfa credential: %w", err)
	}
	return &row, nil
}

// GetMFACredentialsByUserID returns all MFA credentials for a user, ordered by created_at.
func (s *Store) GetMFACredentialsByUserID(ctx context.Context, userID uuid.UUID) ([]generated.MfaCredential, error) {
	var rows []generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		rows, err = q.GetMFACredentialsByUserID(ctx, userID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("get mfa credentials by user: %w", err)
	}
	return rows, nil
}

// GetMFACredentialByUserAndMethod returns the credential for a specific user+method,
// or (nil, nil) if not found.
func (s *Store) GetMFACredentialByUserAndMethod(ctx context.Context, userID uuid.UUID, method string) (*generated.MfaCredential, error) {
	var row generated.MfaCredential
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.GetMFACredentialByUserAndMethod(ctx, generated.GetMFACredentialByUserAndMethodParams{
			UserID: userID,
			Method: method,
		})
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mfa credential by user and method: %w", err)
	}
	return &row, nil
}

// UpdateMFACredentialLastUsed records the last used TOTP step counter and timestamp.
func (s *Store) UpdateMFACredentialLastUsed(ctx context.Context, id uuid.UUID, lastUsedStep sql.NullInt64) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.UpdateMFACredentialLastUsed(ctx, generated.UpdateMFACredentialLastUsedParams{
			ID:           id,
			LastUsedStep: lastUsedStep,
		})
	})
}

// DeleteMFACredential removes a single MFA credential by user and method.
// Returns the number of rows deleted.
func (s *Store) DeleteMFACredential(ctx context.Context, userID uuid.UUID, method string) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.DeleteMFACredential(ctx, generated.DeleteMFACredentialParams{
			UserID: userID,
			Method: method,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("delete mfa credential: %w", err)
	}
	return n, nil
}

// DeleteAllMFACredentials removes all MFA credentials for a user.
// Returns the number of rows deleted.
func (s *Store) DeleteAllMFACredentials(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.DeleteAllMFACredentials(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("delete all mfa credentials: %w", err)
	}
	return n, nil
}

// UserHasMFACredentials returns true if the user has any enrolled MFA methods.
func (s *Store) UserHasMFACredentials(ctx context.Context, userID uuid.UUID) (bool, error) {
	var has bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		has, err = q.UserHasMFACredentials(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("user has mfa credentials: %w", err)
	}
	return has, nil
}

// CountMFACredentialsByUser returns the number of enrolled MFA methods for a user.
func (s *Store) CountMFACredentialsByUser(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountMFACredentialsByUser(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count mfa credentials by user: %w", err)
	}
	return n, nil
}
