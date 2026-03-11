-- ABOUTME: Drops the hardcoded CHECK constraint on cve_sources.source_name.
-- ABOUTME: Custom feed names are validated at the application layer via IsReservedSourceName.

ALTER TABLE cve_sources DROP CONSTRAINT IF EXISTS cve_sources_source_name_check;
