-- migrate:no-transaction
-- ABOUTME: SCIM group and membership tables for IdP group sync.
-- ABOUTME: scim_groups references organizations directly (survives scim_config deletion).

CREATE TABLE IF NOT EXISTS scim_groups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    external_id      TEXT,
    display_name     TEXT NOT NULL,
    mapped_role      TEXT CHECK (mapped_role IN ('viewer', 'member', 'admin')),
    mapped_group_id  UUID REFERENCES groups(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, display_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_id_idx
    ON scim_groups (org_id);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_org_external_id_idx
    ON scim_groups (org_id, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_groups_mapped_group_id_idx
    ON scim_groups (mapped_group_id);

ALTER TABLE scim_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_groups FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_groups
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scim_groups TO cvert_ops_app;

CREATE TABLE IF NOT EXISTS scim_group_members (
    scim_group_id UUID NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scim_group_id, user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_org_id_idx
    ON scim_group_members (org_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS scim_group_members_user_id_idx
    ON scim_group_members (user_id);

ALTER TABLE scim_group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_group_members FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON scim_group_members
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, DELETE ON scim_group_members TO cvert_ops_app;
