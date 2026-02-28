-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS alert_rules_deleted_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rules_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS alert_rules_created_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rules_active_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rules_org_id_idx;

DROP TABLE IF EXISTS alert_rules CASCADE;
