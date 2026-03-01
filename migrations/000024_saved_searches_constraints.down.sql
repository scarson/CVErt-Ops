-- migrate:no-transaction

ALTER TABLE saved_searches DROP CONSTRAINT IF EXISTS saved_searches_nl_query_length;

DROP INDEX CONCURRENTLY IF EXISTS saved_searches_name_uq;
