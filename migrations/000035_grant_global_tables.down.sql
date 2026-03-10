-- Revoke grants added by the up migration.
REVOKE SELECT, INSERT, UPDATE ON cves FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON cve_sources FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON cve_references FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON cve_affected_packages FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON cve_affected_cpes FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON cve_raw_payloads FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE ON cve_search_index FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON epss_staging FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE ON feed_sync_state FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON feed_fetch_log FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE ON cwe_dictionary FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON job_queue FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE, DELETE ON system_jobs_log FROM cvert_ops_app;
REVOKE SELECT, INSERT, UPDATE ON system_settings FROM cvert_ops_app;
