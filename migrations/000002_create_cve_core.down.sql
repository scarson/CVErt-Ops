-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block.

-- Drop in reverse dependency order (children before parents).

DROP TABLE IF EXISTS epss_staging CASCADE;
DROP TABLE IF EXISTS cve_affected_cpes CASCADE;
DROP TABLE IF EXISTS cve_affected_packages CASCADE;
DROP TABLE IF EXISTS cve_references CASCADE;
DROP TABLE IF EXISTS cve_raw_payloads CASCADE;
DROP TABLE IF EXISTS cve_sources CASCADE;
DROP TABLE IF EXISTS cve_search_index CASCADE;
DROP TABLE IF EXISTS cves CASCADE;

DROP EXTENSION IF EXISTS pg_trgm;
