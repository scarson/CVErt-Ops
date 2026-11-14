-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY and DROP INDEX CONCURRENTLY cannot run inside a
-- transaction block (pitfall 11.2). The migration runner executes each statement
-- of this file in its own autocommit.

-- Restores the single-column change-date indexes before dropping the
-- (change date, cve_id) indexes, so no query loses its index.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_modified_canonical_idx
    ON cves (date_modified_canonical DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_epss_updated_idx
    ON cves (date_epss_updated);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_match_inputs_changed_idx
    ON cves (date_match_inputs_changed)
    WHERE date_match_inputs_changed IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS cves_date_modified_canonical_cve_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS cves_date_epss_updated_cve_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS cves_date_match_inputs_changed_cve_id_idx;
