-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall §11.2).

-- ============================================================
-- cwe_dictionary: CWE weakness catalog.
-- Populated by `cvert-ops import-cwe` (Phase 2).
-- ============================================================
CREATE TABLE IF NOT EXISTS cwe_dictionary (
    cwe_id      text    PRIMARY KEY,
    name        text    NOT NULL,
    description text
);

-- ============================================================
-- feed_sync_state: per-feed cursor and health tracking.
-- One row per feed name, upserted after every sync cycle.
-- ============================================================
CREATE TABLE IF NOT EXISTS feed_sync_state (
    feed_name            text        PRIMARY KEY,
    -- Application upsert: ON CONFLICT DO UPDATE SET cursor_json = EXCLUDED.cursor_json
    --   WHERE feed_sync_state.cursor_json IS DISTINCT FROM EXCLUDED.cursor_json
    cursor_json          jsonb,
    last_success_at      timestamptz,
    last_attempt_at      timestamptz,
    consecutive_failures int         NOT NULL DEFAULT 0,
    last_error           text,
    backoff_until        timestamptz
);

-- Autovacuum: this row is updated on every sync cycle for every active feed.
ALTER TABLE feed_sync_state SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 70
);

-- ============================================================
-- feed_fetch_log: audit record for every feed sync attempt.
-- Pruned by the daily retention job (PLAN.md §21).
-- ============================================================
CREATE TABLE IF NOT EXISTS feed_fetch_log (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    feed_name      text        NOT NULL,
    started_at     timestamptz NOT NULL DEFAULT now(),
    ended_at       timestamptz,
    status         text        NOT NULL,    -- 'success' | 'error' | 'partial'
    items_fetched  int         NOT NULL DEFAULT 0,
    items_upserted int         NOT NULL DEFAULT 0,
    cursor_before  jsonb,
    cursor_after   jsonb,
    error_summary  text
);

-- Per-feed history queries and retention cleanup (§21).
CREATE INDEX CONCURRENTLY IF NOT EXISTS feed_fetch_log_feed_started_idx
    ON feed_fetch_log (feed_name, started_at DESC);

-- ============================================================
-- system_jobs_log: audit record for periodic background jobs
-- (retention cleanup, EPSS update, FTS rebuild, etc.).
-- Pruned by the daily retention job (PLAN.md §21).
-- ============================================================
CREATE TABLE IF NOT EXISTS system_jobs_log (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type      text        NOT NULL,
    started_at    timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    status        text        NOT NULL,    -- 'success' | 'error' | 'partial'
    details       jsonb,
    error_summary text
);

-- Per-job-type history queries and retention cleanup (§21).
CREATE INDEX CONCURRENTLY IF NOT EXISTS system_jobs_log_type_started_idx
    ON system_jobs_log (job_type, started_at DESC);
