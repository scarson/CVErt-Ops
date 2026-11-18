-- ABOUTME: Revokes the table privileges migration 000055 granted to cvert_ops_app.
-- ABOUTME: Docker Compose installs must restore them after this runs.

-- On Docker Compose installs these REVOKEs also remove the same privileges
-- granted through the default privileges in docker/init-app-role.sh. The
-- rollback procedure in docs/deployment/upgrading.md has the command that
-- restores them.

REVOKE SELECT ON schema_migrations FROM cvert_ops_app;

REVOKE DELETE ON cve_search_index FROM cvert_ops_app;
REVOKE DELETE ON cves FROM cvert_ops_app;

REVOKE DELETE ON ai_usage_counters FROM cvert_ops_app;

REVOKE SELECT, INSERT, DELETE ON security_events FROM cvert_ops_app;
