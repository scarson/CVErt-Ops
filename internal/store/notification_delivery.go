// ABOUTME: Store methods for the notification_deliveries delivery job queue.
// ABOUTME: Worker ops use withBypassTx; API-facing ops (List, Get, Replay) use withOrgTx.
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

// ClaimedDelivery is the row returned by ClaimPendingDeliveries.
type ClaimedDelivery = generated.ClaimPendingDeliveriesRow

// upsertDeliverySQL is the debounce INSERT: creates a pending delivery or appends the
// CVE snapshot to an existing pending row for the same (rule_id, channel_id) pair.
// The ON CONFLICT targets the partial unique index (rule_id, channel_id) WHERE status='pending'.
const upsertDeliverySQL = `
INSERT INTO notification_deliveries (org_id, rule_id, channel_id, payload, send_after)
VALUES ($1, $2, $3, jsonb_build_array($4::jsonb), now() + ($5 * interval '1 second'))
ON CONFLICT (rule_id, channel_id) WHERE status = 'pending'
DO UPDATE SET
    payload    = notification_deliveries.payload || jsonb_build_array($4::jsonb),
    send_after = now() + ($5 * interval '1 second'),
    updated_at = now()`

// UpsertDelivery creates a pending delivery row or, if a pending row already exists for
// the same (rule_id, channel_id), appends the CVE snapshot to its payload array.
// debounceSeconds controls when send_after is set (debounce window or retry backoff).
// Uses withBypassTx because the delivery worker is cross-tenant.
func (s *Store) UpsertDelivery(ctx context.Context, orgID, ruleID, channelID uuid.UUID, payload []byte, debounceSeconds int) error {
	err := s.withBypassTx(ctx, func(_ *generated.Queries) error {
		_, err := s.db.ExecContext(ctx, upsertDeliverySQL,
			orgID,
			ruleID,
			channelID,
			payload,
			debounceSeconds,
		)
		return err
	})
	if err != nil {
		return fmt.Errorf("upsert delivery: %w", err)
	}
	return nil
}

// ClaimPendingDeliveries claims up to limit pending delivery rows that are ready to send
// (send_after <= now()). Uses FOR UPDATE SKIP LOCKED for concurrent-worker safety.
func (s *Store) ClaimPendingDeliveries(ctx context.Context, limit int) ([]ClaimedDelivery, error) {
	var result []ClaimedDelivery
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		result, err = q.ClaimPendingDeliveries(ctx, int32(limit)) //nolint:gosec // G115: limit validated by caller
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("claim pending deliveries: %w", err)
	}
	return result, nil
}

// MarkDeliveriesProcessing transitions the given delivery IDs from pending to processing.
func (s *Store) MarkDeliveriesProcessing(ctx context.Context, ids []uuid.UUID) error {
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.MarkDeliveriesProcessing(ctx, ids)
	})
	if err != nil {
		return fmt.Errorf("mark deliveries processing: %w", err)
	}
	return nil
}

// CompleteDelivery marks a delivery as succeeded.
func (s *Store) CompleteDelivery(ctx context.Context, id uuid.UUID) error {
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.CompleteDelivery(ctx, id)
	})
	if err != nil {
		return fmt.Errorf("complete delivery: %w", err)
	}
	return nil
}

// RetryDelivery moves a delivery back to pending with incremented attempt_count and a
// backoff delay of backoffSeconds. lastError records the most recent failure message.
func (s *Store) RetryDelivery(ctx context.Context, id uuid.UUID, backoffSeconds int, lastError string) error {
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.RetryDelivery(ctx, generated.RetryDeliveryParams{
			ID:        id,
			Column2:   backoffSeconds,
			LastError: sql.NullString{String: lastError, Valid: lastError != ""},
		})
	})
	if err != nil {
		return fmt.Errorf("retry delivery: %w", err)
	}
	return nil
}

// ExhaustDelivery marks a delivery as permanently failed (max attempts reached).
func (s *Store) ExhaustDelivery(ctx context.Context, id uuid.UUID, lastError string) error {
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ExhaustDelivery(ctx, generated.ExhaustDeliveryParams{
			ID:        id,
			LastError: sql.NullString{String: lastError, Valid: lastError != ""},
		})
	})
	if err != nil {
		return fmt.Errorf("exhaust delivery: %w", err)
	}
	return nil
}

// ResetStuckDeliveries resets processing rows that have not been updated within
// stuckThreshold back to pending so they can be reclaimed by a healthy worker.
func (s *Store) ResetStuckDeliveries(ctx context.Context, stuckThreshold time.Duration) error {
	thresholdSeconds := int(stuckThreshold.Seconds())
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		return q.ResetStuckDeliveries(ctx, thresholdSeconds)
	})
	if err != nil {
		return fmt.Errorf("reset stuck deliveries: %w", err)
	}
	return nil
}

// OrphanedAlertEvents returns alert events that fired but have no corresponding delivery row,
// up to limit results. Used by the recovery scanner to re-enqueue missing deliveries.
func (s *Store) OrphanedAlertEvents(ctx context.Context, limit int) ([]generated.OrphanedAlertEventsRow, error) {
	var result []generated.OrphanedAlertEventsRow
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		result, err = q.OrphanedAlertEvents(ctx, int32(limit)) //nolint:gosec // G115: limit validated by caller
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("orphaned alert events: %w", err)
	}
	return result, nil
}

// ListDeliveries returns delivery rows for an org, optionally filtered by rule, channel,
// and status. Uses keyset pagination on (created_at DESC, id DESC).
func (s *Store) ListDeliveries(ctx context.Context, orgID uuid.UUID, ruleID, channelID uuid.NullUUID, status *string, cursorTime time.Time, cursorID uuid.UUID, limit int) ([]generated.ListDeliveriesRow, error) {
	var result []generated.ListDeliveriesRow
	// Translate nullable UUIDs: uuid.NullUUID → uuid.UUID (zero value when not set).
	var ruleIDVal, channelIDVal uuid.UUID
	if ruleID.Valid {
		ruleIDVal = ruleID.UUID
	}
	if channelID.Valid {
		channelIDVal = channelID.UUID
	}
	var statusVal string
	if status != nil {
		statusVal = *status
	}
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		var err error
		result, err = q.ListDeliveries(ctx, generated.ListDeliveriesParams{
			OrgID:     orgID,
			Column2:   ruleIDVal,
			Column3:   channelIDVal,
			Column4:   statusVal,
			CreatedAt: cursorTime,
			ID:        cursorID,
			Limit:     int32(limit), //nolint:gosec // G115: limit validated by caller
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	return result, nil
}

// GetDelivery returns the delivery row with the given id within orgID, or nil if not found.
func (s *Store) GetDelivery(ctx context.Context, id, orgID uuid.UUID) (*generated.NotificationDelivery, error) {
	var result *generated.NotificationDelivery
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		row, err := q.GetDelivery(ctx, generated.GetDeliveryParams{
			ID:    id,
			OrgID: orgID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("get delivery: %w", err)
		}
		result = &row
		return nil
	})
	return result, err
}

// ReplayDelivery resets a failed or cancelled delivery back to pending with attempt_count=0.
// No-ops silently if the delivery is not in a replayable state.
func (s *Store) ReplayDelivery(ctx context.Context, id, orgID uuid.UUID) error {
	err := s.withOrgTx(ctx, orgID, func(q *generated.Queries) error {
		return q.ReplayDelivery(ctx, generated.ReplayDeliveryParams{
			ID:    id,
			OrgID: orgID,
		})
	})
	if err != nil {
		return fmt.Errorf("replay delivery: %w", err)
	}
	return nil
}
