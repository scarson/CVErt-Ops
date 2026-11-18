-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS cve_cna_affected_package_key_idx;
DROP INDEX CONCURRENTLY IF EXISTS cve_cna_affected_check_idx;
DROP INDEX CONCURRENTLY IF EXISTS cve_cpe_matches_check_idx;
DROP INDEX CONCURRENTLY IF EXISTS cve_affected_packages_check_idx;
ALTER TABLE cve_cna_affected DROP COLUMN IF EXISTS package_key;
