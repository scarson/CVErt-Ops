-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS ai_request_log_created_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS ai_request_log_org_id_idx;
DROP TABLE IF EXISTS ai_request_log;
