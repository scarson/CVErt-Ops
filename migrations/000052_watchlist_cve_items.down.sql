-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- Postgres cannot remove a value from an enum, so 'cve' stays in
-- watchlist_item_type with no rows using it. The up migration adds it with
-- IF NOT EXISTS, so re-applying is safe.

DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_cve_changed_idx;
DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_cve_uq;

DELETE FROM watchlist_items WHERE item_type = 'cve';

ALTER TABLE watchlist_items DROP CONSTRAINT IF EXISTS wi_cve_fields;
ALTER TABLE watchlist_items DROP COLUMN IF EXISTS cve_id;
