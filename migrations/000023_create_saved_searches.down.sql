-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS saved_searches_user_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS saved_searches_org_id_idx;
DROP TABLE IF EXISTS saved_searches;
