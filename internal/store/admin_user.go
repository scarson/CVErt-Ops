// ABOUTME: Store methods for site admin user management.
// ABOUTME: All methods use withBypassTx — admin operates across all orgs.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"

	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// AdminUserRow holds a single row from the admin user listing query.
type AdminUserRow struct {
	ID               uuid.UUID  `json:"id"`
	Email            string     `json:"email"`
	DisplayName      string     `json:"display_name"`
	IsSiteAdmin      bool       `json:"is_site_admin"`
	LastLoginAt      *time.Time `json:"last_login_at"`
	CreatedAt        time.Time  `json:"created_at"`
	DisabledAt       *time.Time `json:"disabled_at"`
	LockedAt         *time.Time `json:"locked_at"`
	ForcePasswdReset bool       `json:"force_password_reset"`
	OrgCount         int64      `json:"org_count"`
}

// AdminListUsers lists users with keyset pagination, sorted by created_at desc.
func (s *Store) AdminListUsers(ctx context.Context, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AdminUserRow, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	sb := psql.
		Select(
			"u.id",
			"u.email",
			"u.display_name",
			"u.is_site_admin",
			"u.last_login_at",
			"u.created_at",
			"u.disabled_at",
			"u.locked_at",
			"u.force_password_reset",
			"COUNT(om.org_id) AS org_count",
		).
		From("users u").
		LeftJoin("org_members om ON om.user_id = u.id").
		GroupBy("u.id").
		OrderBy("u.created_at DESC", "u.id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if afterTime != nil && afterID != nil {
		sb = sb.Where("(u.created_at, u.id) < (?, ?)", *afterTime, *afterID)
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("admin list users: build query: %w", err)
	}

	result := make([]AdminUserRow, 0)
	err = s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("admin list users: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var r AdminUserRow
			var lastLoginAt sql.NullTime
			var disabledAt sql.NullTime
			var lockedAt sql.NullTime
			if err := rows.Scan(
				&r.ID, &r.Email, &r.DisplayName, &r.IsSiteAdmin,
				&lastLoginAt, &r.CreatedAt, &disabledAt, &lockedAt,
				&r.ForcePasswdReset, &r.OrgCount,
			); err != nil {
				return fmt.Errorf("admin list users: scan: %w", err)
			}
			r.LastLoginAt = fromNullTime(lastLoginAt)
			r.DisabledAt = fromNullTime(disabledAt)
			r.LockedAt = fromNullTime(lockedAt)
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
}

// AdminGetUserByID retrieves a single user by ID.
func (s *Store) AdminGetUserByID(ctx context.Context, userID uuid.UUID) (*generated.User, error) {
	var user generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		user, err = q.AdminGetUserByID(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AdminDisableUser sets disabled_at on a user.
func (s *Store) AdminDisableUser(ctx context.Context, userID uuid.UUID) (*generated.User, error) {
	var user generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		user, err = q.AdminDisableUser(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AdminEnableUser clears disabled_at on a user.
func (s *Store) AdminEnableUser(ctx context.Context, userID uuid.UUID) (*generated.User, error) {
	var user generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		user, err = q.AdminEnableUser(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AdminUnlockUser clears locked_at and resets failed_login_count.
func (s *Store) AdminUnlockUser(ctx context.Context, userID uuid.UUID) (*generated.User, error) {
	var user generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		user, err = q.AdminUnlockUser(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// AdminForcePasswordReset sets force_password_reset flag on a user.
func (s *Store) AdminForcePasswordReset(ctx context.Context, userID uuid.UUID) (*generated.User, error) {
	var user generated.User
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		user, err = q.AdminForcePasswordReset(ctx, userID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &user, nil
}
