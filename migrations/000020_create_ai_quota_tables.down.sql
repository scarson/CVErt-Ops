-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS ai_quota_overrides_org_id_idx;
DROP TABLE IF EXISTS ai_quota_overrides;

DROP INDEX CONCURRENTLY IF EXISTS ai_usage_counters_org_id_idx;
DROP TABLE IF EXISTS ai_usage_counters;
