-- migrate:no-transaction
-- ABOUTME: Creates group_members join table with denormalized org_id for RLS.
-- ABOUTME: org_id must be denormalized — RLS on groups does NOT protect group_members.

CREATE TABLE IF NOT EXISTS group_members (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id   uuid        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT group_members_pkey PRIMARY KEY (id),
    CONSTRAINT group_members_unique UNIQUE (group_id, user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS group_members_org_idx   ON group_members (org_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS group_members_group_idx ON group_members (group_id);

GRANT SELECT, INSERT, DELETE ON group_members TO cvert_ops_app;

ALTER TABLE group_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_members FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON group_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
