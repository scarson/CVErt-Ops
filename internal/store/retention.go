// ABOUTME: Store wrappers for bounded-batch retention cleanup queries.
// ABOUTME: All methods use withBypassTx — retention is a cross-org background worker operation.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// CleanupCveRawPayloads deletes up to batchSize rows older than cutoff.
func (s *Store) CleanupCveRawPayloads(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupCveRawPayloads(ctx, generated.CleanupCveRawPayloadsParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup cve_raw_payloads: %w", err)
	}
	return n, nil
}

// CleanupFeedFetchLog deletes up to batchSize rows older than cutoff.
func (s *Store) CleanupFeedFetchLog(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupFeedFetchLog(ctx, generated.CleanupFeedFetchLogParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup feed_fetch_log: %w", err)
	}
	return n, nil
}

// CleanupAlertEvents deletes up to batchSize rows for the given orgs older than cutoff.
func (s *Store) CleanupAlertEvents(ctx context.Context, orgIDs []uuid.UUID, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupAlertEvents(ctx, generated.CleanupAlertEventsParams{
			OrgIds:    orgIDs,
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup alert_events: %w", err)
	}
	return n, nil
}

// CleanupNotificationDeliveries deletes up to batchSize rows for the given orgs older than cutoff.
func (s *Store) CleanupNotificationDeliveries(ctx context.Context, orgIDs []uuid.UUID, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupNotificationDeliveries(ctx, generated.CleanupNotificationDeliveriesParams{
			OrgIds:    orgIDs,
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup notification_deliveries: %w", err)
	}
	return n, nil
}

// CleanupJobQueue deletes up to batchSize succeeded/dead rows older than cutoff.
func (s *Store) CleanupJobQueue(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupJobQueue(ctx, generated.CleanupJobQueueParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup job_queue: %w", err)
	}
	return n, nil
}

// CleanupRefreshTokens deletes up to batchSize expired tokens older than cutoff.
// Caller should compute cutoff = now() - grace window (e.g., 60s).
func (s *Store) CleanupRefreshTokens(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupRefreshTokens(ctx, generated.CleanupRefreshTokensParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup refresh_tokens: %w", err)
	}
	return n, nil
}

// CleanupAIRequestLogBatch deletes up to batchSize rows older than cutoff.
func (s *Store) CleanupAIRequestLogBatch(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupAIRequestLog(ctx, generated.CleanupAIRequestLogParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup ai_request_log: %w", err)
	}
	return n, nil
}

// CleanupAICacheBatch deletes up to batchSize expired cache entries.
func (s *Store) CleanupAICacheBatch(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupAICache(ctx, generated.CleanupAICacheParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup ai_cache: %w", err)
	}
	return n, nil
}

// CleanupAIUsageCounters deletes up to batchSize daily usage rows older than cutoff date.
func (s *Store) CleanupAIUsageCounters(ctx context.Context, cutoff time.Time, batchSize int) (int64, error) {
	var n int64
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		n, err = q.CleanupAIUsageCounters(ctx, generated.CleanupAIUsageCountersParams{
			Cutoff:    cutoff,
			BatchSize: int32(batchSize), //nolint:gosec // G115: batch sizes are always small
		})
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cleanup ai_usage_counters: %w", err)
	}
	return n, nil
}
