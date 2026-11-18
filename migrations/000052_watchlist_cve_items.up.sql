-- migrate:no-transaction
-- ALTER TYPE ... ADD VALUE must commit before the new value can be used, and
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block. The migration
-- runner executes each statement of this file in its own autocommit, which
-- satisfies both (MultiStatementEnabled, simple query protocol).

ALTER TYPE watchlist_item_type ADD VALUE IF NOT EXISTS 'cve';

-- No foreign key to cves: a host scanner can report a CVE that no feed has
-- delivered yet, and the item starts matching when the CVE arrives.
ALTER TABLE watchlist_items
    ADD COLUMN IF NOT EXISTS cve_id TEXT NULL CHECK (char_length(cve_id) <= 32);

ALTER TABLE watchlist_items
    ADD CONSTRAINT wi_cve_fields CHECK (item_type != 'cve' OR cve_id IS NOT NULL);

-- Partial unique: one active CVE entry per (watchlist, cve_id). Also serves the
-- per-CVE probe in the alert rule watchlist filter.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_cve_uq
    ON watchlist_items (watchlist_id, cve_id)
    WHERE item_type = 'cve' AND deleted_at IS NULL;

-- The batch and EPSS alert evaluators poll for CVE items added or removed since
-- their cursor. GREATEST ignores NULL, so a live item sorts by created_at and a
-- removed item by deleted_at.
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_cve_changed_idx
    ON watchlist_items (GREATEST(created_at, deleted_at))
    WHERE item_type = 'cve';
