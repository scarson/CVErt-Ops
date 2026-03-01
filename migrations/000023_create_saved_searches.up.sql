-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

CREATE TABLE IF NOT EXISTS saved_searches (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
    name       TEXT        NOT NULL CHECK (char_length(name) <= 255),
    query_json JSONB       NOT NULL,
    nl_query   TEXT,
    is_shared  BOOLEAN     NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

ALTER TABLE saved_searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE saved_searches FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON saved_searches
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Soft-delete for normal operations; hard-delete for orphan cleanup on user deletion.
GRANT SELECT, INSERT, UPDATE, DELETE ON saved_searches TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS saved_searches_org_id_idx
    ON saved_searches (org_id);

-- User's private searches.
CREATE INDEX CONCURRENTLY IF NOT EXISTS saved_searches_user_id_idx
    ON saved_searches (user_id)
    WHERE deleted_at IS NULL;
