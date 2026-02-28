-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

-- Enables ON CONFLICT dedup for alert:realtime jobs:
--   INSERT INTO job_queue ... ON CONFLICT (lock_key) WHERE status IN ('pending','running') DO NOTHING
-- The existing job_queue_lock_key_running_uq only covers status='running' and cannot
-- serve as the conflict target for this broader predicate.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS job_queue_lock_key_active
    ON job_queue (lock_key)
    WHERE status IN ('pending', 'running');
