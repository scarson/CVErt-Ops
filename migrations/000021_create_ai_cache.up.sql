-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

CREATE TABLE IF NOT EXISTS ai_cache (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    feature        TEXT        NOT NULL CHECK (feature IN ('nl_search', 'summarize')),
    prompt_version TEXT        NOT NULL,
    input_hash     TEXT        NOT NULL,
    response       JSONB       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL
);

ALTER TABLE ai_cache ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_cache FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON ai_cache
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_cache TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_cache_org_id_idx
    ON ai_cache (org_id);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS ai_cache_lookup_idx
    ON ai_cache (org_id, feature, prompt_version, input_hash);

-- Retention cleanup: find expired rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_cache_expires_at_idx
    ON ai_cache (expires_at);
