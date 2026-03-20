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

	"github.com/scarson/cvert-ops/internal/dbutil"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CreateUser inserts a new user row. Returns the created user.
// Pass an empty passwordHash for OAuth-only accounts.
// Uses withBypassTx — runs during registration before org context is established.
func (s *Store) CreateUser(ctx context.Context, email, displayName, passwordHash string, hashVersion int) (*generated.User, error) {
	var row generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.CreateUser(ctx, generated.CreateUserParams{
			Email:               email,
			DisplayName:         displayName,
			PasswordHash:        dbutil.NullString(passwordHash),
			PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
		})
		return err
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

// CountUsers returns the total number of user rows (including soft-deleted ones).
// Used for first-user org bootstrap detection during registration.
// Uses withBypassTx — runs during registration before org context is established.
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CountUsers(ctx)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return n, nil
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
// Uses withBypassTx — runs from password reset/change flows before org context.
func (s *Store) UpdatePasswordHash(ctx context.Context, id uuid.UUID, passwordHash string, hashVersion int) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.UpdatePasswordHash(ctx, generated.UpdatePasswordHashParams{
			ID:                  id,
			PasswordHash:        dbutil.NullString(passwordHash),
			PasswordHashVersion: int32(hashVersion), //nolint:gosec // hashVersion is a small constant (1-255)
		}); err != nil {
			return fmt.Errorf("update password hash: %w", err)
		}
		return nil
	})
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

// IsSiteAdmin returns whether the given user has the site admin flag set.
// Uses withBypassTx since it runs from middleware before org context is established.
func (s *Store) IsSiteAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var isAdmin bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		isAdmin, err = q.IsSiteAdmin(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("is site admin: %w", err)
	}
	return isAdmin, nil
}

// IsUserEnabled returns true if the user exists and is not disabled.
// Used by auth middleware to reject disabled users. Uses withBypassTx since
// it runs from middleware before org context is established.
func (s *Store) IsUserEnabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	var enabled bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		enabled, err = q.IsUserEnabled(ctx, userID)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("is user enabled: %w", err)
	}
	return enabled, nil
}

// SetFirstSiteAdmin atomically promotes a user to site admin only if no admin exists yet.
// Uses withBypassTx since it runs during registration before org context.
func (s *Store) SetFirstSiteAdmin(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.SetFirstSiteAdmin(ctx, userID)
	})
}

// UserAuthStatus holds the auth-relevant flags for a user.
type UserAuthStatus struct {
	Enabled            bool
	ForcePasswordReset bool
}

// GetUserAuthStatus returns the enabled and force_password_reset status for a user.
// Uses withBypassTx since it runs from auth middleware before org context.
func (s *Store) GetUserAuthStatus(ctx context.Context, userID uuid.UUID) (*UserAuthStatus, error) {
	var status UserAuthStatus
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetUserAuthStatus(ctx, userID)
		if err != nil {
			return err
		}
		status.Enabled = row.Enabled
		status.ForcePasswordReset = row.ForcePasswordReset
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get user auth status: %w", err)
	}
	return &status, nil
}

// ClearForcePasswordReset clears the force_password_reset flag for a user.
// Uses withBypassTx since it runs from change-password flow before org context.
func (s *Store) ClearForcePasswordReset(ctx context.Context, userID uuid.UUID) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ClearForcePasswordReset(ctx, userID)
	})
}

// LoginLockoutState holds the lockout-relevant fields for a user.
type LoginLockoutState struct {
	FailedCount int32
	LockedAt    *time.Time
}

// RecordLoginFailure atomically increments the failed login count and locks the
// account if the threshold is reached. Returns the resulting lockout state.
// Uses withBypassTx since it runs from the login flow before org context.
func (s *Store) RecordLoginFailure(ctx context.Context, email string, threshold int) (*LoginLockoutState, error) {
	var state LoginLockoutState
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.RecordLoginFailure(ctx, generated.RecordLoginFailureParams{
			Email:     email,
			Threshold: int32(threshold), //nolint:gosec // threshold is a small config constant (1-100)
		})
		if err != nil {
			return err
		}
		state.FailedCount = row.FailedLoginCount
		if row.LockedAt.Valid {
			t := row.LockedAt.Time
			state.LockedAt = &t
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("record login failure: %w", err)
	}
	return &state, nil
}

// RecordLoginSuccess resets lockout state after a successful login.
// Uses withBypassTx since it runs from the login flow before org context.
func (s *Store) RecordLoginSuccess(ctx context.Context, email string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.RecordLoginSuccess(ctx, email)
	})
}

// GetLoginLockoutState returns the lockout state for a user by email.
// Uses withBypassTx since it runs from the login flow before org context.
func (s *Store) GetLoginLockoutState(ctx context.Context, email string) (*LoginLockoutState, error) {
	var state LoginLockoutState
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		row, err := q.GetLoginLockoutState(ctx, email)
		if err != nil {
			return err
		}
		state.FailedCount = row.FailedLoginCount
		if row.LockedAt.Valid {
			t := row.LockedAt.Time
			state.LockedAt = &t
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("get login lockout state: %w", err)
	}
	return &state, nil
}

// UpdateUserEmail updates a user's email address.
// Uses withBypassTx — users is a global table with no RLS.
func (s *Store) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.UpdateUserEmail(ctx, generated.UpdateUserEmailParams{
			ID:    id,
			Email: email,
		}); err != nil {
			return fmt.Errorf("update user email: %w", err)
		}
		return nil
	})
}

// UpdateUserDisplayName updates a user's display name.
// Uses withBypassTx — users is a global table with no RLS.
func (s *Store) UpdateUserDisplayName(ctx context.Context, id uuid.UUID, displayName string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.UpdateUserDisplayName(ctx, generated.UpdateUserDisplayNameParams{
			ID:          id,
			DisplayName: displayName,
		}); err != nil {
			return fmt.Errorf("update user display name: %w", err)
		}
		return nil
	})
}

// UpdateUserProfile updates a user's email and display name in one statement.
// Uses withBypassTx — users is a global table with no RLS.
func (s *Store) UpdateUserProfile(ctx context.Context, id uuid.UUID, email, displayName string) error {
	return s.withBypassTx(ctx, func(q *generated.Queries) error {
		if err := q.UpdateUserProfile(ctx, generated.UpdateUserProfileParams{
			ID:          id,
			Email:       email,
			DisplayName: displayName,
		}); err != nil {
			return fmt.Errorf("update user profile: %w", err)
		}
		return nil
	})
}

// ListIdentitiesByProviderAndUsers returns all identity rows for a provider
// and set of user IDs. Used by SCIM list users to batch-load external IDs.
func (s *Store) ListIdentitiesByProviderAndUsers(ctx context.Context, provider string, userIDs []uuid.UUID) ([]generated.UserIdentity, error) {
	rows, err := s.q.ListIdentitiesByProviderAndUsers(ctx, generated.ListIdentitiesByProviderAndUsersParams{
		Provider: provider,
		Column2:  userIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("list identities by provider and users: %w", err)
	}
	return rows, nil
}

// GetIdentityByProviderAndUser returns the identity row for a provider+user,
// or (nil, nil) if not found.
func (s *Store) GetIdentityByProviderAndUser(ctx context.Context, provider string, userID uuid.UUID) (*generated.UserIdentity, error) {
	row, err := s.q.GetIdentityByProviderAndUser(ctx, generated.GetIdentityByProviderAndUserParams{
		Provider: provider,
		UserID:   userID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get identity by provider and user: %w", err)
	}
	return &row, nil
}
