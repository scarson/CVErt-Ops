-- migrate:no-transaction
-- ABOUTME: Creates org_members join table (user ↔ org role assignments).
-- ABOUTME: First org-scoped table: includes full RLS policy (PLAN.md §6.2).

CREATE TABLE org_members (
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text        NOT NULL,  -- 'owner', 'admin', 'member', 'viewer'
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_members_pkey PRIMARY KEY (org_id, user_id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS org_members_org_idx  ON org_members (org_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS org_members_user_idx ON org_members (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON org_members TO cvert_ops_app;

-- ── RLS (PLAN.md §6.2) ────────────────────────────────────────────────────
ALTER TABLE org_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_members FORCE ROW LEVEL SECURITY;

-- Policy: visible only when app.org_id matches, or worker bypass is set.
-- Both settings use missing_ok=TRUE so an unset variable returns NULL,
-- which evaluates to FALSE in USING — fail-closed by design.
CREATE POLICY org_isolation ON org_members
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
