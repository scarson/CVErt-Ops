-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block.

-- Drop in reverse creation order.
DROP TABLE IF EXISTS system_jobs_log CASCADE;
DROP TABLE IF EXISTS feed_fetch_log CASCADE;
DROP TABLE IF EXISTS feed_sync_state CASCADE;
DROP TABLE IF EXISTS cwe_dictionary CASCADE;
