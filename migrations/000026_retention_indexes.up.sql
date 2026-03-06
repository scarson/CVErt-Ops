-- migrate:no-transaction

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_raw_payloads_ingested_at_idx
    ON cve_raw_payloads (ingested_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS feed_fetch_log_started_at_idx
    ON feed_fetch_log (started_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS job_queue_cleanup_idx
    ON job_queue (finished_at) WHERE status IN ('succeeded', 'dead');
