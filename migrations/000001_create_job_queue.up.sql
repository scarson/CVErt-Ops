-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

CREATE TABLE IF NOT EXISTS job_queue (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    queue        text        NOT NULL,                -- 'feed_ingest', 'notify', 'report', 'cleanup'
    priority     int         NOT NULL DEFAULT 0,      -- higher = more urgent
    payload      jsonb       NOT NULL,

    -- Optional lock/dedupe key to constrain concurrency for a class of jobs.
    -- Examples: 'feed:nvd', 'feed:mitre', 'cleanup:retention'
    lock_key     text        NULL,

    status       text        NOT NULL DEFAULT 'pending', -- pending | running | succeeded | dead
    run_after    timestamptz NOT NULL DEFAULT now(),

    attempts     int         NOT NULL DEFAULT 0,
    max_attempts int         NOT NULL DEFAULT 3,

    locked_by    text        NULL,      -- worker ID
    locked_at    timestamptz NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz NULL,
    last_error   text        NULL
);

-- Aggressive autovacuum and fill-factor required for high-churn job queue tables.
-- Without this, dead tuples accumulate and SKIP LOCKED polling degrades significantly
-- (pitfall §18.1 / PLAN.md §18.1 "Job queue MVCC storage tuning").
ALTER TABLE job_queue SET (
    autovacuum_vacuum_scale_factor = 0.01, -- vacuum when 1% dead (vs default 20%)
    autovacuum_vacuum_cost_delay   = 2,    -- vacuum more aggressively (ms per I/O cost window)
    fillfactor                     = 70    -- reserve 30% free space per page for HOT updates
);

-- Fast polling of runnable jobs ordered by queue, then priority descending.
CREATE INDEX CONCURRENTLY IF NOT EXISTS job_queue_runnable_idx
    ON job_queue (queue, status, run_after, priority DESC);

-- At most one RUNNING job per lock_key (NULL lock_key jobs are unconstrained).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS job_queue_lock_key_running_uq
    ON job_queue (lock_key)
    WHERE lock_key IS NOT NULL AND status = 'running';
