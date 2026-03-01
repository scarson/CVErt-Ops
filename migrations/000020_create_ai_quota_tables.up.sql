-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

-- ── ai_usage_counters ───────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_usage_counters (
    org_id        UUID   NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    feature       TEXT   NOT NULL CHECK (feature IN ('nl_search', 'summarize')),
    date          DATE   NOT NULL DEFAULT CURRENT_DATE,
    count         INT    NOT NULL DEFAULT 0,
    input_tokens  INT    NOT NULL DEFAULT 0,
    output_tokens INT    NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, feature, date)
);

ALTER TABLE ai_usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_usage_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON ai_usage_counters
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE ON ai_usage_counters TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_usage_counters_org_id_idx
    ON ai_usage_counters (org_id);

-- ── ai_quota_overrides ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ai_quota_overrides (
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    feature     TEXT NOT NULL CHECK (feature IN ('nl_search', 'summarize')),
    daily_limit INT  NOT NULL CHECK (daily_limit >= 0),
    PRIMARY KEY (org_id, feature)
);

ALTER TABLE ai_quota_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_quota_overrides FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON ai_quota_overrides
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON ai_quota_overrides TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS ai_quota_overrides_org_id_idx
    ON ai_quota_overrides (org_id);
