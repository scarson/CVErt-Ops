// ABOUTME: Store methods for site admin delivery management (cross-org).
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

// AdminDeliveryRow holds a single row from the admin delivery listing query.
type AdminDeliveryRow struct {
	ID              uuid.UUID    `json:"id"`
	OrgID           uuid.UUID    `json:"org_id"`
	RuleID          *uuid.UUID   `json:"rule_id,omitempty"`
	ChannelID       uuid.UUID    `json:"channel_id"`
	Kind            string       `json:"kind"`
	Status          string       `json:"status"`
	AttemptCount    int32        `json:"attempt_count"`
	SendAfter       time.Time    `json:"send_after"`
	LastAttemptedAt *time.Time   `json:"last_attempted_at,omitempty"`
	DeliveredAt     *time.Time   `json:"delivered_at,omitempty"`
	LastError       string       `json:"last_error,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
}

// AdminListDeliveries lists deliveries across all orgs with optional status filter
// and keyset pagination. Sorted by created_at desc.
func (s *Store) AdminListDeliveries(ctx context.Context, status string, afterTime *time.Time, afterID *uuid.UUID, limit int) ([]AdminDeliveryRow, error) {
	psql := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

	sb := psql.
		Select(
			"id", "org_id", "rule_id", "channel_id", "kind", "status",
			"attempt_count", "send_after", "last_attempted_at", "delivered_at",
			"last_error", "created_at", "updated_at",
		).
		From("notification_deliveries").
		OrderBy("created_at DESC", "id DESC").
		Limit(uint64(limit)) //nolint:gosec // G115: limit validated by caller

	if status != "" {
		sb = sb.Where("status = ?", status)
	}

	if afterTime != nil && afterID != nil {
		sb = sb.Where("(created_at, id) < (?, ?)", *afterTime, *afterID)
	}

	query, args, err := sb.ToSql()
	if err != nil {
		return nil, fmt.Errorf("admin list deliveries: build query: %w", err)
	}

	result := make([]AdminDeliveryRow, 0)
	err = s.withBypassRawTx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("admin list deliveries: %w", err)
		}
		defer rows.Close() //nolint:errcheck

		for rows.Next() {
			var r AdminDeliveryRow
			var ruleID uuid.NullUUID
			var lastAttemptedAt sql.NullTime
			var deliveredAt sql.NullTime
			var lastError sql.NullString
			if err := rows.Scan(
				&r.ID, &r.OrgID, &ruleID, &r.ChannelID, &r.Kind, &r.Status,
				&r.AttemptCount, &r.SendAfter, &lastAttemptedAt, &deliveredAt,
				&lastError, &r.CreatedAt, &r.UpdatedAt,
			); err != nil {
				return fmt.Errorf("admin list deliveries: scan: %w", err)
			}
			if ruleID.Valid {
				r.RuleID = &ruleID.UUID
			}
			r.LastAttemptedAt = fromNullTime(lastAttemptedAt)
			r.DeliveredAt = fromNullTime(deliveredAt)
			r.LastError = fromNullString(lastError)
			result = append(result, r)
		}
		return rows.Err()
	})
	return result, err
}

// AdminGetDeliveryByID retrieves a single delivery by ID (cross-org).
func (s *Store) AdminGetDeliveryByID(ctx context.Context, id uuid.UUID) (*generated.AdminGetDeliveryByIDRow, error) {
	var row generated.AdminGetDeliveryByIDRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		row, err = q.AdminGetDeliveryByID(ctx, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &row, nil
}

// AdminRetryDelivery retries a single failed delivery. Returns the number of rows affected.
func (s *Store) AdminRetryDelivery(ctx context.Context, id uuid.UUID) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		result, err := q.AdminRetryDelivery(ctx, id)
		if err != nil {
			return err
		}
		n, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("admin retry delivery: %w", err)
	}
	return n, nil
}

// AdminBulkRetryFailed retries up to limit failed deliveries. Returns the number of rows affected.
func (s *Store) AdminBulkRetryFailed(ctx context.Context, limit int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		result, err := q.AdminBulkRetryFailed(ctx, int32(limit)) //nolint:gosec // G115: limit validated by caller
		if err != nil {
			return err
		}
		n, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("admin bulk retry failed: %w", err)
	}
	return n, nil
}
