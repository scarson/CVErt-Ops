-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_cpe_uq;
DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_pkg_uq;
DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_watchlist_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS watchlist_items_org_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS watchlists_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS watchlists_created_at_idx;
DROP INDEX CONCURRENTLY IF EXISTS watchlists_group_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS watchlists_org_id_idx;

DROP TABLE IF EXISTS watchlist_items CASCADE;
DROP TABLE IF EXISTS watchlists CASCADE;
DROP TYPE  IF EXISTS watchlist_item_type;
