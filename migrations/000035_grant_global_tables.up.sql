-- Grant cvert_ops_app access to global tables that were missing GRANTs.
-- These tables have no RLS (they are global/shared data), but the app role
-- still needs explicit privileges to read/write them.

-- CVE core tables (global, no RLS)
GRANT SELECT, INSERT, UPDATE ON cves TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_sources TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_references TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_affected_packages TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_affected_cpes TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_raw_payloads TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE ON cve_search_index TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON epss_staging TO cvert_ops_app;

-- Feed state tables (global, no RLS)
GRANT SELECT, INSERT, UPDATE ON feed_sync_state TO cvert_ops_app;
GRANT SELECT, INSERT ON feed_fetch_log TO cvert_ops_app;

-- Reference data (global, no RLS)
GRANT SELECT, INSERT, UPDATE ON cwe_dictionary TO cvert_ops_app;

-- Job queue (global, no RLS)
GRANT SELECT, INSERT, UPDATE, DELETE ON job_queue TO cvert_ops_app;

-- System tables (global, no RLS)
GRANT SELECT, INSERT ON system_jobs_log TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE ON system_settings TO cvert_ops_app;
