-- ABOUTME: Grants cvert_ops_app the table privileges for statements the application runs.
-- ABOUTME: Covers security events, retention purges, CVE alias promotion and the schema version check.

-- Privileges cvert_ops_app needs for statements the application runs. Docker
-- Compose installs also receive table privileges from the default privileges in
-- docker/init-app-role.sh. Every other install has only what migrations grant.

-- The security event writer inserts, the admin API lists, and retention purges
-- (store.CleanupSecurityEvents). Events are never edited, so there is no UPDATE.
GRANT SELECT, INSERT, DELETE ON security_events TO cvert_ops_app;

-- Retention purges daily usage rows (store.CleanupAIUsageCounters).
GRANT DELETE ON ai_usage_counters TO cvert_ops_app;

-- Merge pipeline alias promotion (merge.migrateCVEPK): promoting a native
-- advisory ID to a CVE ID deletes its search index row, and merging it into an
-- existing CVE also deletes its cves row.
GRANT DELETE ON cves TO cvert_ops_app;
GRANT DELETE ON cve_search_index TO cvert_ops_app;

-- /readyz, the doctor command and the startup schema check read the applied
-- version. golang-migrate creates this table before running the first migration.
GRANT SELECT ON schema_migrations TO cvert_ops_app;
