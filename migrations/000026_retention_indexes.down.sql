-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS job_queue_cleanup_idx;
DROP INDEX CONCURRENTLY IF EXISTS feed_fetch_log_started_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS cve_raw_payloads_ingested_at_idx;
