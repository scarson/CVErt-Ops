-- ABOUTME: Restores the hardcoded CHECK constraint on cve_sources.source_name.
-- ABOUTME: Reverses 000038_relax_cve_sources_source_name_check.up.sql.

ALTER TABLE cve_sources ADD CONSTRAINT cve_sources_source_name_check
    CHECK (source_name IN ('mitre', 'nvd', 'osv', 'ghsa', 'kev', 'epss', 'msrc', 'redhat'))
    NOT VALID;
ALTER TABLE cve_sources VALIDATE CONSTRAINT cve_sources_source_name_check;
