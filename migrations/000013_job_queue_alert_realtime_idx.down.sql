-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS job_queue_lock_key_active;
