-- migrate:no-transaction
-- ABOUTME: Drops cve_vendor_enrichment and the CHECK constraint on cve_sources.

ALTER TABLE cve_sources DROP CONSTRAINT IF EXISTS cve_sources_source_name_check;

DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_enrichment;
DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_fix_state;
DROP INDEX CONCURRENTLY IF EXISTS idx_cve_vendor_enrichment_severity;

DROP TABLE IF EXISTS cve_vendor_enrichment;
