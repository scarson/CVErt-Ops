-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

CREATE TABLE IF NOT EXISTS ai_request_log (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id        UUID        NOT NULL,
    feature        TEXT        NOT NULL CHECK (feature IN ('nl_search', 'summarize')),
    input_hash     TEXT        NOT NULL,
    prompt_version TEXT        NOT NULL,
    model          TEXT        NOT NULL,
    cache_hit      BOOLEAN     NOT NULL,
    input_tokens   INT,
    output_tokens  INT,
    latency_ms     INT         NOT NULL,
    status         TEXT        NOT NULL CHECK (status IN ('success', 'error')),
    error_type     TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ai_request_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_request_log FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON ai_request_log
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- user_id is NOT a FK — log survives user deletion as an audit record.
GRANT SELECT, INSERT, DELETE ON ai_request_log TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_request_log_org_id_idx
    ON ai_request_log (org_id);

-- Retention cleanup: delete rows older than 90 days.
CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_request_log_created_at_idx
    ON ai_request_log (org_id, created_at);
