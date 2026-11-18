-- ABOUTME: Makes every RLS policy treat an empty app.org_id as no org context.
-- ABOUTME: Postgres leaves a custom setting as '' after SET LOCAL, and ''::uuid raises an error.

ALTER POLICY org_isolation ON ai_cache
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON ai_quota_overrides
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON ai_request_log
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON ai_usage_counters
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON alert_events
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON alert_rule_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON alert_rule_runs
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON alert_rules
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON api_keys
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON audit_log
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON group_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON groups
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY mfa_requirements_policy ON mfa_requirements
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON notification_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON notification_deliveries
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON org_invitations
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON org_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON report_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON saved_searches
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON scheduled_reports
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON scim_configs
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON scim_group_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON scim_groups
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON sso_connections
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON sso_email_domains
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON watchlist_items
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );

ALTER POLICY org_isolation ON watchlists
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = NULLIF(current_setting('app.org_id', TRUE), '')::uuid
    );
