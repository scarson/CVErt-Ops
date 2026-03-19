// ABOUTME: Store methods for the job queue — claim, complete, fail, recover stale, and enqueue.
// ABOUTME: Wraps sqlc-generated queries with domain types and error formatting.
//
// Most methods use s.q (bound to the raw pool) rather than a transaction helper.
// The jobs table is not org-scoped and has no RLS policies, so withOrgTx provides
// no safety benefit. HasPendingOrRunningJob uses withBypassTx because it runs
// within an existing handler flow that needs transaction isolation.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/scarson/cvert-ops/internal/dbutil"
	generated "github.com/scarson/cvert-ops/internal/store/generated"
)

// Job is a claimed job ready for execution by the worker pool.
type Job struct {
	ID       uuid.UUID
	Queue    string
	Payload  json.RawMessage
	Attempts int32
}

// ClaimJob atomically claims one pending job from the named queue for the
// given workerID using FOR UPDATE SKIP LOCKED. Returns (nil, nil) when no
// job is currently available.
func (s *Store) ClaimJob(ctx context.Context, queue, workerID string) (*Job, error) {
	row, err := s.q.ClaimJob(ctx, generated.ClaimJobParams{
		Queue:    queue,
		LockedBy: dbutil.NullString(workerID),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("claim job: %w", err)
	}
	return &Job{
		ID:       row.ID,
		Queue:    row.Queue,
		Payload:  row.Payload,
		Attempts: row.Attempts,
	}, nil
}

// CompleteJob marks a job as succeeded.
func (s *Store) CompleteJob(ctx context.Context, id uuid.UUID) error {
	if err := s.q.CompleteJob(ctx, id); err != nil {
		return fmt.Errorf("complete job %s: %w", id, err)
	}
	return nil
}

// FailJob marks a job as failed, applying exponential backoff for retry or
// moving it to 'dead' status if max_attempts is exhausted.
func (s *Store) FailJob(ctx context.Context, id uuid.UUID, errMsg string) error {
	if err := s.q.FailJob(ctx, generated.FailJobParams{
		ID:        id,
		LastError: dbutil.NullString(errMsg),
	}); err != nil {
		return fmt.Errorf("fail job %s: %w", id, err)
	}
	return nil
}

// RecoverStaleJobs resets jobs stuck in 'running' state longer than staleAfter
// back to 'pending'. Returns the number of jobs recovered.
func (s *Store) RecoverStaleJobs(ctx context.Context, staleAfter time.Duration) (int, error) {
	rows, err := s.q.RecoverStaleJobs(ctx, int64(staleAfter.Seconds()))
	if err != nil {
		return 0, fmt.Errorf("recover stale jobs: %w", err)
	}
	return len(rows), nil
}

// CountPendingJobs returns the number of jobs in 'pending' status across all queues.
func (s *Store) CountPendingJobs(ctx context.Context) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx, "SELECT count(*) FROM job_queue WHERE status = 'pending'").Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count pending jobs: %w", err)
	}
	return count, nil
}

// EnqueueJob inserts a new job into the named queue and returns its ID.
// lockKey prevents concurrent execution of jobs with the same key.
// runAfter defaults to now() when nil.
// Returns (uuid.Nil, nil) when a pending/running job with the same lock_key
// already exists (ON CONFLICT DO NOTHING).
func (s *Store) EnqueueJob(
	ctx context.Context,
	queue string,
	priority int32,
	payload json.RawMessage,
	lockKey *string,
	maxAttempts int32,
	runAfter *time.Time,
) (uuid.UUID, error) {
	lk := dbutil.NullStringPtr(lockKey)

	var ra interface{}
	if runAfter != nil {
		ra = *runAfter
	}

	id, err := s.q.EnqueueJob(ctx, generated.EnqueueJobParams{
		Queue:       queue,
		Priority:    priority,
		Payload:     payload,
		LockKey:     lk,
		MaxAttempts: maxAttempts,
		Column6:     ra,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil // dedup: job with same lock_key already pending/running
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("enqueue job: %w", err)
	}
	return id, nil
}

// HasPendingOrRunningJob checks if a job with the given lock_key exists in pending or running state.
func (s *Store) HasPendingOrRunningJob(ctx context.Context, lockKey string) (bool, error) {
	var has bool
	err := s.withBypassTx(ctx, func(q *generated.Queries) error {
		var err error
		has, err = q.HasPendingOrRunningJob(ctx, lockKey)
		return err
	})
	if err != nil {
		return false, fmt.Errorf("has pending or running job: %w", err)
	}
	return has, nil
}
