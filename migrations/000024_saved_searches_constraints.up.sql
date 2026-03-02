-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

-- Partial unique index: one active saved search per (org, user, name).
-- Scoped to user_id so different users in the same org can reuse names.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS saved_searches_name_uq
    ON saved_searches (org_id, user_id, name)
    WHERE deleted_at IS NULL;

-- Length constraint on nl_query to prevent unbounded input.
ALTER TABLE saved_searches
    ADD CONSTRAINT saved_searches_nl_query_length
    CHECK (char_length(nl_query) <= 1000);
