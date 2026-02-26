-- name: ClaimJob :one
-- SKIP LOCKED: skip rows locked by other workers; returns nil if no job available.
-- Atomically increments attempts and sets status=running in one round trip.
UPDATE job_queue
SET
    status    = 'running',
    locked_by = $2,
    locked_at = now(),
    attempts  = attempts + 1
WHERE id = (
    SELECT jq.id
    FROM job_queue jq
    WHERE jq.queue = $1
      AND jq.status = 'pending'
      AND jq.run_after <= now()
    ORDER BY jq.priority DESC, jq.created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING *;

-- name: CompleteJob :exec
UPDATE job_queue
SET
    status      = 'succeeded',
    finished_at = now(),
    locked_by   = NULL,
    locked_at   = NULL
WHERE id = $1;

-- name: FailJob :exec
-- Moves job to 'pending' with exponential backoff, or 'dead' if attempts exhausted.
-- Note: attempts was already incremented by ClaimJob.
UPDATE job_queue
SET
    last_error  = $2,
    locked_by   = NULL,
    locked_at   = NULL,
    status      = CASE
                      WHEN attempts >= max_attempts THEN 'dead'
                      ELSE 'pending'
                  END,
    run_after   = CASE
                      WHEN attempts >= max_attempts THEN run_after
                      ELSE now() + (power(2, attempts) * interval '1 second')
                  END,
    finished_at = CASE
                      WHEN attempts >= max_attempts THEN now()
                      ELSE NULL
                  END
WHERE id = $1;

-- name: RecoverStaleJobs :many
-- Resets jobs stuck in 'running' state longer than the given number of seconds.
-- Called by the stale-lock recovery goroutine every minute.
-- $1 is the stale threshold in whole seconds (e.g. 300 = 5 minutes).
-- Uses integer multiplication instead of ::interval cast — pgx sends int64
-- as binary int8 which PostgreSQL cannot cast directly to interval (pitfall).
UPDATE job_queue
SET
    status    = 'pending',
    locked_by = NULL,
    locked_at = NULL
WHERE status = 'running'
  AND locked_at < now() - ($1 * INTERVAL '1 second')
RETURNING id, queue, lock_key;

-- name: EnqueueJob :one
INSERT INTO job_queue (queue, priority, payload, lock_key, max_attempts, run_after)
VALUES ($1, $2, $3, $4, $5, coalesce($6, now()))
RETURNING id;
