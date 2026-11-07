-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

-- The retention job hard-deletes watchlist items that were soft-deleted longer
-- ago than RETENTION_WATCHLIST_ITEMS_DAYS (PLAN.md §21.2). Replacing a
-- watchlist's items soft-deletes every dropped row, so without a purge the
-- table grows with each replacement.
GRANT DELETE ON watchlist_items TO cvert_ops_app;

-- Serves the retention purge (deleted_at < cutoff ORDER BY deleted_at). Partial,
-- so it holds only removed items and live-item writes do not maintain it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_deleted_at_idx
    ON watchlist_items (deleted_at)
    WHERE deleted_at IS NOT NULL;
