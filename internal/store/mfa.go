// ABOUTME: Store methods for MFA credential and recovery code operations.
// ABOUTME: All operations use withBypassTx — MFA tables are global (no RLS).
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

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

// recoveryCodeCount is the number of recovery codes generated per user.
const recoveryCodeCount = 10

// generateRecoveryCode produces a single recovery code in xxxxx-xxxxx format (a-z0-9).
func generateRecoveryCode() (string, error) {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 10)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		b[i] = chars[idx.Int64()]
	}
	return string(b[:5]) + "-" + string(b[5:]), nil
}

// hashRecoveryCode returns the SHA-256 hex digest of a normalized recovery code.
// Normalization: lowercase, strip dashes — so users can type codes in any format.
func hashRecoveryCode(code string) string {
	normalized := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}

// GenerateRecoveryCodes creates 10 one-time recovery codes for the user.
// Returns the plaintext codes (shown to the user once); only hashes are stored.
func (s *Store) GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		codes[i] = code
	}

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		for _, code := range codes {
			err := q.CreateMFARecoveryCode(ctx, generated.CreateMFARecoveryCodeParams{
				UserID:   userID,
				CodeHash: hashRecoveryCode(code),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("generate recovery codes: %w", err)
	}
	return codes, nil
}

// VerifyRecoveryCode checks a recovery code and marks it used if valid.
// Returns (success, remaining_unused_count, error).
// Uses SELECT FOR UPDATE SKIP LOCKED to prevent concurrent double-consumption.
func (s *Store) VerifyRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (bool, int, error) {
	var ok bool
	var remaining int64

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		h := hashRecoveryCode(code)

		row, err := q.GetUnusedRecoveryCodeByHashForUpdate(ctx, generated.GetUnusedRecoveryCodeByHashForUpdateParams{
			UserID:   userID,
			CodeHash: h,
		})
		if errors.Is(err, sql.ErrNoRows) {
			// Code not found or already used; count remaining and return.
			remaining, err = q.CountUnusedRecoveryCodes(ctx, userID)
			if err != nil {
				return err
			}
			ok = false
			return nil
		}
		if err != nil {
			return err
		}

		// Mark the code as consumed.
		if err := q.MarkRecoveryCodeUsed(ctx, row.ID); err != nil {
			return err
		}

		remaining, err = q.CountUnusedRecoveryCodes(ctx, userID)
		if err != nil {
			return err
		}
		ok = true
		return nil
	})
	if err != nil {
		return false, 0, fmt.Errorf("verify recovery code: %w", err)
	}
	return ok, int(remaining), nil
}

// RegenerateRecoveryCodes deletes all existing codes and generates a fresh set.
// Returns the new plaintext codes.
func (s *Store) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	for i := range codes {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		codes[i] = code
	}

	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		if _, err := q.DeleteAllRecoveryCodes(ctx, userID); err != nil {
			return err
		}
		for _, code := range codes {
			err := q.CreateMFARecoveryCode(ctx, generated.CreateMFARecoveryCodeParams{
				UserID:   userID,
				CodeHash: hashRecoveryCode(code),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("regenerate recovery codes: %w", err)
	}
	return codes, nil
}

// DeleteAllRecoveryCodes removes all recovery codes for a user.
func (s *Store) DeleteAllRecoveryCodes(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		_, err := q.DeleteAllRecoveryCodes(ctx, userID)
		return err
	})
}

// CountUnusedRecoveryCodes returns the number of unused recovery codes for a user.
func (s *Store) CountUnusedRecoveryCodes(ctx context.Context, userID uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountUnusedRecoveryCodes(ctx, userID)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count unused recovery codes: %w", err)
	}
	return n, nil
}
