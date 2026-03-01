-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS ai_cache_expires_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS ai_cache_lookup_idx;
DROP INDEX CONCURRENTLY IF EXISTS ai_cache_org_id_idx;
DROP TABLE IF EXISTS ai_cache;
