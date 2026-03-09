// ABOUTME: Store methods for password reset token operations.
// ABOUTME: Global table (no org_id, no RLS) — uses withBypassTx for auth-path consistency.
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

// PasswordResetToken is the application-level representation of a password reset token.
type PasswordResetToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    sql.NullTime
	CreatedAt time.Time
}

// CreatePasswordResetToken inserts a hashed password reset token for the given user.
func (s *Store) CreatePasswordResetToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.CreatePasswordResetToken(ctx, generated.CreatePasswordResetTokenParams{
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: expiresAt,
		})
	})
}

// ConsumePasswordResetToken atomically looks up a valid token and marks it used.
// Returns (nil, nil) if the token doesn't exist, is expired, or was already consumed.
func (s *Store) ConsumePasswordResetToken(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error) {
	var tok *PasswordResetToken
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.ConsumePasswordResetToken(ctx, tokenHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tok = &PasswordResetToken{
			ID:        row.ID,
			UserID:    row.UserID,
			ExpiresAt: row.ExpiresAt,
			UsedAt:    row.UsedAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("consume password reset token: %w", err)
	}
	return tok, nil
}

// GetPasswordResetTokenByHash returns the valid (unused, unexpired) token matching the hash,
// or (nil, nil) if not found.
func (s *Store) GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error) {
	var tok *PasswordResetToken
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetPasswordResetTokenByHash(ctx, tokenHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tok = &PasswordResetToken{
			ID:        row.ID,
			UserID:    row.UserID,
			ExpiresAt: row.ExpiresAt,
			UsedAt:    row.UsedAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get password reset token by hash: %w", err)
	}
	return tok, nil
}

// MarkPasswordResetTokenUsed marks a token as used.
func (s *Store) MarkPasswordResetTokenUsed(ctx context.Context, tokenID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.MarkPasswordResetTokenUsed(ctx, tokenID)
	})
}

// CountRecentPasswordResetTokens returns the number of password reset tokens
// created for a user since the given time.
func (s *Store) CountRecentPasswordResetTokens(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	var count int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		count, err = q.CountRecentPasswordResetTokens(ctx, generated.CountRecentPasswordResetTokensParams{
			UserID:    userID,
			CreatedAt: since,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count recent password reset tokens: %w", err)
	}
	return count, nil
}

// DeleteExpiredPasswordResetTokens removes all expired password reset tokens.
func (s *Store) DeleteExpiredPasswordResetTokens(ctx context.Context) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.DeleteExpiredPasswordResetTokens(ctx)
	})
}
