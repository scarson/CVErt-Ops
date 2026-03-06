-- migrate:no-transaction
-- ABOUTME: Creates cve_vendor_enrichment for vendor-specific CVE metadata.
-- ABOUTME: Adds CHECK constraints on source_name for both new and existing tables.

CREATE TABLE IF NOT EXISTS cve_vendor_enrichment (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id            TEXT        NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    source_name       TEXT        NOT NULL
                      CHECK (source_name IN ('kev', 'msrc', 'redhat')),
    vendor_severity   TEXT,
    vendor_fix_state  TEXT,
    enrichment        JSONB       NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(cve_id, source_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_severity
    ON cve_vendor_enrichment (vendor_severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_fix_state
    ON cve_vendor_enrichment (vendor_fix_state);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_cve_vendor_enrichment_enrichment
    ON cve_vendor_enrichment USING gin (enrichment);

ALTER TABLE cve_vendor_enrichment SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 80
);

GRANT SELECT, INSERT, UPDATE, DELETE ON cve_vendor_enrichment TO cvert_ops_app;

-- Add CHECK constraint to existing cve_sources table (validates existing source names).
-- DROP + ADD for idempotency (golang-migrate doesn't support DO $$ blocks).
ALTER TABLE cve_sources DROP CONSTRAINT IF EXISTS cve_sources_source_name_check;
ALTER TABLE cve_sources ADD CONSTRAINT cve_sources_source_name_check
    CHECK (source_name IN ('mitre', 'nvd', 'osv', 'ghsa', 'kev', 'epss', 'msrc', 'redhat'))
    NOT VALID;
ALTER TABLE cve_sources VALIDATE CONSTRAINT cve_sources_source_name_check;
