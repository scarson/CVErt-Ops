-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.
-- The plain indexes cannot be built while a stored CPE is over the btree row limit,
-- so delete such rows before migrating down.

DROP INDEX CONCURRENTLY IF EXISTS cve_cpe_matches_check_idx;

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((cpe_normalized COLLATE "C"));

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_eco_pkg_idx
    ON cve_affected_packages (ecosystem, package_name);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cpe_normalized_idx
    ON cve_affected_cpes (cpe_normalized);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cve_cpe_uq
    ON cve_affected_cpes (cve_id, cpe_normalized);

DROP INDEX CONCURRENTLY IF EXISTS cve_affected_cpes_cve_cpe_digest_uq;
