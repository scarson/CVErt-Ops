-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_type_created;
DROP INDEX CONCURRENTLY IF EXISTS idx_security_events_created_at;
DROP TABLE IF EXISTS security_events;
