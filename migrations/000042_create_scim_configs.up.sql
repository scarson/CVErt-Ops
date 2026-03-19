-- migrate:no-transaction

-- ABOUTME: SCIM provisioning config table (1:1 with orgs via sso_connections).
-- ABOUTME: Bearer token stored as sha256 hash. Separate from API key infrastructure.

CREATE TABLE IF NOT EXISTS scim_configs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    sso_connection_id UUID NOT NULL UNIQUE REFERENCES sso_connections(id) ON DELETE CASCADE,
    enabled           BOOLEAN NOT NULL DEFAULT false,
    token_hash        TEXT NOT NULL,
    token_prefix      TEXT NOT NULL,
    default_role      TEXT NOT NULL DEFAULT 'viewer'
                      CHECK (default_role IN ('viewer', 'member')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_configs_token_hash_idx
    ON scim_configs (token_hash);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_configs_org_id_idx
    ON scim_configs (org_id);

ALTER TABLE scim_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_configs FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_configs
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_configs TO cvert_ops_app;
