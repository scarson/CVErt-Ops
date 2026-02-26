// ABOUTME: Store methods for user authentication: creation, lookup, token versioning.
// ABOUTME: These are global-table operations — no orgID parameter, no RLS.
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

// CreateUser inserts a new user row. Returns the created user.
// Pass an empty passwordHash for OAuth-only accounts.
func (s *Store) CreateUser(ctx context.Context, email, displayName, passwordHash string, hashVersion int) (*generated.User, error) {
	row, err := s.q.CreateUser(ctx, generated.CreateUserParams{
		Email:               email,
		DisplayName:         displayName,
		PasswordHash:        sql.NullString{String: passwordHash, Valid: passwordHash != ""},
		PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
	})
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &row, nil
}

// GetUserByID returns the user with the given ID, or (nil, nil) if not found.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*generated.User, error) {
	row, err := s.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	return &row, nil
}

// GetUserByEmail returns the user with the given email, or (nil, nil) if not found.
// SECURITY: call only from auth flows — never from org-admin endpoints.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*generated.User, error) {
	row, err := s.q.GetUserByEmail(ctx, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	return &row, nil
}

// UpdateLastLogin sets last_login_at to now for the given user.
func (s *Store) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	if err := s.q.UpdateLastLogin(ctx, id); err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	return nil
}

// IncrementTokenVersion increments token_version and returns the new value.
// Used by logout-all to immediately invalidate all outstanding refresh tokens.
func (s *Store) IncrementTokenVersion(ctx context.Context, id uuid.UUID) (int32, error) {
	v, err := s.q.IncrementTokenVersion(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("increment token version: %w", err)
	}
	return v, nil
}

// UpdatePasswordHash replaces the password hash and bumps token_version to
// invalidate all active sessions (forces re-login after password change).
func (s *Store) UpdatePasswordHash(ctx context.Context, id uuid.UUID, passwordHash string, hashVersion int) error {
	if err := s.q.UpdatePasswordHash(ctx, generated.UpdatePasswordHashParams{
		ID:                  id,
		PasswordHash:        sql.NullString{String: passwordHash, Valid: passwordHash != ""},
		PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
	}); err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	return nil
}

// UpsertUserIdentity creates or updates a user_identities row for the given provider.
func (s *Store) UpsertUserIdentity(ctx context.Context, userID uuid.UUID, provider, providerUserID, email string) error {
	if err := s.q.UpsertUserIdentity(ctx, generated.UpsertUserIdentityParams{
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          email,
	}); err != nil {
		return fmt.Errorf("upsert user identity: %w", err)
	}
	return nil
}

// GetUserByProviderID returns the user linked to the given OAuth provider identity,
// or (nil, nil) if no such identity exists.
func (s *Store) GetUserByProviderID(ctx context.Context, provider, providerUserID string) (*generated.User, error) {
	row, err := s.q.GetUserByProviderID(ctx, generated.GetUserByProviderIDParams{
		Provider:       provider,
		ProviderUserID: providerUserID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user by provider id: %w", err)
	}
	return &row, nil
}

// CreateRefreshToken inserts a new refresh token row.
func (s *Store) CreateRefreshToken(ctx context.Context, jti, userID uuid.UUID, tokenVersion int, expiresAt time.Time) error {
	if err := s.q.CreateRefreshToken(ctx, generated.CreateRefreshTokenParams{
		Jti:          jti,
		UserID:       userID,
		TokenVersion: int32(tokenVersion), //nolint:gosec // tokenVersion is a small counter
		ExpiresAt:    expiresAt,
	}); err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken returns the refresh token for the given JTI, or (nil, nil) if not found.
func (s *Store) GetRefreshToken(ctx context.Context, jti uuid.UUID) (*generated.RefreshToken, error) {
	row, err := s.q.GetRefreshToken(ctx, jti)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get refresh token: %w", err)
	}
	return &row, nil
}

// MarkRefreshTokenUsed sets used_at and records the JTI of the replacement token.
func (s *Store) MarkRefreshTokenUsed(ctx context.Context, jti, replacedByJTI uuid.UUID) error {
	if err := s.q.MarkRefreshTokenUsed(ctx, generated.MarkRefreshTokenUsedParams{
		Jti:           jti,
		ReplacedByJti: uuid.NullUUID{UUID: replacedByJTI, Valid: true},
	}); err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}
	return nil
}

// DeleteExpiredRefreshTokens removes tokens expired more than 60 seconds ago.
// Returns the number of rows deleted.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	n, err := s.q.DeleteExpiredRefreshTokens(ctx)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	return n, nil
}
