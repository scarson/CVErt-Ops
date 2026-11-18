-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY and DROP INDEX CONCURRENTLY cannot run inside a
-- transaction block (pitfall 11.2). The migration runner executes each statement
-- of this file in its own autocommit.

-- The batch and EPSS evaluators page through the CVEs changed after their cursor
-- with a (change date, cve_id) keyset, one scan per date column, so each page
-- starts where the last one ended in the index. Each composite index replaces
-- the single-column index on the same date: it serves every query the
-- single-column index served, and a backward scan of the date_modified_canonical
-- index gives the "date_modified_canonical DESC, cve_id DESC" order of search
-- and saved searches. The new indexes are built before the old ones are dropped,
-- so no query loses its index during the deploy.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_modified_canonical_cve_id_idx
    ON cves (date_modified_canonical, cve_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_epss_updated_cve_id_idx
    ON cves (date_epss_updated, cve_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_match_inputs_changed_cve_id_idx
    ON cves (date_match_inputs_changed, cve_id)
    WHERE date_match_inputs_changed IS NOT NULL;

DROP INDEX CONCURRENTLY IF EXISTS cves_date_modified_canonical_idx;
DROP INDEX CONCURRENTLY IF EXISTS cves_date_epss_updated_idx;
DROP INDEX CONCURRENTLY IF EXISTS cves_date_match_inputs_changed_idx;
