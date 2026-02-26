package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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
		LockedBy: sql.NullString{String: workerID, Valid: true},
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
		LastError: sql.NullString{String: errMsg, Valid: errMsg != ""},
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

// EnqueueJob inserts a new job into the named queue and returns its ID.
// lockKey prevents concurrent execution of jobs with the same key.
// runAfter defaults to now() when nil.
func (s *Store) EnqueueJob(
	ctx context.Context,
	queue string,
	priority int32,
	payload json.RawMessage,
	lockKey *string,
	maxAttempts int32,
	runAfter *time.Time,
) (uuid.UUID, error) {
	var lk sql.NullString
	if lockKey != nil {
		lk = sql.NullString{String: *lockKey, Valid: true}
	}

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
	if err != nil {
		return uuid.Nil, fmt.Errorf("enqueue job: %w", err)
	}
	return id, nil
}
