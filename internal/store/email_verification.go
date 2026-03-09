// ABOUTME: Store methods for email verification token operations.
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

// EmailVerificationToken is the application-level representation of an email verification token.
type EmailVerificationToken struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	ExpiresAt time.Time
	UsedAt    sql.NullTime
	CreatedAt time.Time
}

// CreateEmailVerificationToken inserts a hashed email verification token for the given user.
func (s *Store) CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt time.Time) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.CreateEmailVerificationToken(ctx, generated.CreateEmailVerificationTokenParams{
			UserID:    userID,
			TokenHash: tokenHash,
			ExpiresAt: expiresAt,
		})
	})
}

// GetEmailVerificationTokenByHash returns the valid (unused, unexpired) token matching the hash,
// or (nil, nil) if not found.
func (s *Store) GetEmailVerificationTokenByHash(ctx context.Context, tokenHash []byte) (*EmailVerificationToken, error) {
	var tok *EmailVerificationToken
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetEmailVerificationTokenByHash(ctx, tokenHash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tok = &EmailVerificationToken{
			ID:        row.ID,
			UserID:    row.UserID,
			ExpiresAt: row.ExpiresAt,
			UsedAt:    row.UsedAt,
			CreatedAt: row.CreatedAt,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get email verification token by hash: %w", err)
	}
	return tok, nil
}

// MarkEmailVerificationTokenUsed marks a verification token as used.
func (s *Store) MarkEmailVerificationTokenUsed(ctx context.Context, tokenID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.MarkEmailVerificationTokenUsed(ctx, tokenID)
	})
}

// SetEmailVerified sets email_verified = true for the given user.
func (s *Store) SetEmailVerified(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.SetEmailVerified(ctx, userID)
	})
}

// CountRecentEmailVerificationTokens returns the number of email verification tokens
// created for a user since the given time.
func (s *Store) CountRecentEmailVerificationTokens(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	var count int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		count, err = q.CountRecentEmailVerificationTokens(ctx, generated.CountRecentEmailVerificationTokensParams{
			UserID:    userID,
			CreatedAt: since,
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count recent email verification tokens: %w", err)
	}
	return count, nil
}

// DeleteExpiredEmailVerificationTokens removes all expired verification tokens.
func (s *Store) DeleteExpiredEmailVerificationTokens(ctx context.Context) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.DeleteExpiredEmailVerificationTokens(ctx)
	})
}
