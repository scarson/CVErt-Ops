-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS alert_events_unresolved_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_events_cve_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_events_first_fired_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_events_rule_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_events_org_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rule_runs_started_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rule_runs_rule_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS alert_rule_runs_org_id_idx;

DROP TABLE IF EXISTS alert_events CASCADE;
DROP TABLE IF EXISTS alert_rule_runs CASCADE;
