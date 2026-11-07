-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_deleted_at_idx;

REVOKE DELETE ON watchlist_items FROM cvert_ops_app;
