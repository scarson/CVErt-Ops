-- On Docker Compose installs these REVOKEs also remove the same privileges
-- granted through the default privileges in docker/init-app-role.sh.

REVOKE SELECT ON schema_migrations FROM cvert_ops_app;

REVOKE DELETE ON cve_search_index FROM cvert_ops_app;
REVOKE DELETE ON cves FROM cvert_ops_app;

REVOKE DELETE ON ai_usage_counters FROM cvert_ops_app;

REVOKE SELECT, INSERT, DELETE ON security_events FROM cvert_ops_app;
