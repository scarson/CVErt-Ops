// ABOUTME: Store methods for site admin organization management.
// ABOUTME: All methods use withBypassTx — admin is not a member of target orgs.
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

// AdminOrgRow holds a single row from the admin org listing query.
type AdminOrgRow struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Tier           string     `json:"tier"`
	MemberCount    int64      `json:"member_count"`
	CreatedAt      time.Time  `json:"created_at"`
	SuspendedAt    *time.Time `json:"suspended_at"`
	LastActivityAt *time.Time `json:"last_activity_at"`
}

// AdminListOrgs lists organizations with keyset pagination, sorted by created_at desc.
// afterTime/afterID form the keyset cursor. limit is the max rows returned.
func (s *Store) AdminListOrgs(ctx context.Context, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AdminOrgRow, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	sb := psql.
		Select(
			"o.id",
			"o.name",
			"o.tier",
			"COUNT(om.user_id) AS member_count",
			"o.created_at",
			"o.suspended_at",
			"MAX(u.last_login_at) AS last_activity_at",
		).
		From("organizations o").
		LeftJoin("org_members om ON om.org_id = o.id").
		LeftJoin("users u ON u.id = om.user_id").
		Where("o.deleted_at IS NULL").
		GroupBy("o.id").
		OrderBy("o.created_at DESC", "o.id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if afterTime != nil && afterID != nil {
		sb = sb.Where("(o.created_at, o.id) < (?, ?)", *afterTime, *afterID)
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("admin list orgs: build query: %w", err)
	}

	result := make([]AdminOrgRow, 0)
	err = s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("admin list orgs: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var r AdminOrgRow
			var suspendedAt sql.NullTime
			var lastActivityAt sql.NullTime
			if err := rows.Scan(
				&r.ID, &r.Name, &r.Tier, &r.MemberCount,
				&r.CreatedAt, &suspendedAt, &lastActivityAt,
			); err != nil {
				return fmt.Errorf("admin list orgs: scan: %w", err)
			}
			r.SuspendedAt = fromNullTime(suspendedAt)
			r.LastActivityAt = fromNullTime(lastActivityAt)
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
}

// AdminGetOrgByID retrieves a single organization by ID (including deleted).
func (s *Store) AdminGetOrgByID(ctx context.Context, orgID uuid.UUID) (*generated.Organization, error) {
	var org generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		org, err = q.AdminGetOrgByID(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// AdminUpdateOrgTier updates the tier for an organization.
func (s *Store) AdminUpdateOrgTier(ctx context.Context, orgID uuid.UUID, tier string) (*generated.Organization, error) {
	var org generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		org, err = q.AdminUpdateOrgTier(ctx, generated.AdminUpdateOrgTierParams{
			ID:   orgID,
			Tier: tier,
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// AdminSuspendOrg sets suspended_at on an organization.
func (s *Store) AdminSuspendOrg(ctx context.Context, orgID uuid.UUID) (*generated.Organization, error) {
	var org generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		org, err = q.AdminSuspendOrg(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// AdminUnsuspendOrg clears suspended_at on an organization.
func (s *Store) AdminUnsuspendOrg(ctx context.Context, orgID uuid.UUID) (*generated.Organization, error) {
	var org generated.Organization
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		org, err = q.AdminUnsuspendOrg(ctx, orgID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &org, nil
}

// AdminOrgUsage holds resource counts for a single organization.
type AdminOrgUsage struct {
	Rules      int64 `json:"rules"`
	Watchlists int64 `json:"watchlists"`
	Members    int64 `json:"members"`
	Channels   int64 `json:"channels"`
}

// AdminGetOrgUsage returns resource counts for an organization.
func (s *Store) AdminGetOrgUsage(ctx context.Context, orgID uuid.UUID) (*AdminOrgUsage, error) {
	var usage AdminOrgUsage
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		usage.Rules, err = q.AdminCountOrgAlertRules(ctx, orgID)
		if err != nil {
			return fmt.Errorf("count rules: %w", err)
		}
		usage.Watchlists, err = q.AdminCountOrgWatchlists(ctx, orgID)
		if err != nil {
			return fmt.Errorf("count watchlists: %w", err)
		}
		usage.Members, err = q.AdminCountOrgMembers(ctx, orgID)
		if err != nil {
			return fmt.Errorf("count members: %w", err)
		}
		usage.Channels, err = q.AdminCountOrgChannels(ctx, orgID)
		if err != nil {
			return fmt.Errorf("count channels: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &usage, nil
}
