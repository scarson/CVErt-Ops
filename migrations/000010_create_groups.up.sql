-- migrate:no-transaction
-- ABOUTME: Creates the groups table for org-scoped user collections.
-- ABOUTME: Used for notification routing and watchlist ownership. Soft-deletable.

CREATE TABLE groups (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL,
    CONSTRAINT groups_pkey PRIMARY KEY (id)
);

-- Partial unique index: allows name reuse after soft-delete (PLAN.md Appendix A).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS groups_name_uq
    ON groups (org_id, name)
    WHERE deleted_at IS NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS groups_org_idx ON groups (org_id);

GRANT SELECT, INSERT, UPDATE ON groups TO cvert_ops_app;

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE groups FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON groups
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
