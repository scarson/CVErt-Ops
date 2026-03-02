-- migrate:no-transaction

CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,          -- NOT a FK; audit records survive org deletion
    actor_id    UUID,                   -- NULL for system actions; NOT a FK
    actor_email TEXT,                   -- NULL for system actions; denormalized
    action      TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    entity_type TEXT NOT NULL,          -- 'alert_rule', 'channel', 'watchlist', etc.
    entity_id   TEXT NOT NULL,          -- UUID as text (supports different PK types)
    entity_name TEXT,                   -- denormalized display name at write time
    success     BOOLEAN NOT NULL DEFAULT true,  -- false for denied mutation attempts
    old_state   JSONB,                  -- NULL for create / denied attempts
    new_state   JSONB,                  -- NULL for delete / denied attempts
    metadata    JSONB,                  -- IP, user agent, API key prefix, request ID
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_org_created_idx
    ON audit_log (org_id, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_entity_idx
    ON audit_log (org_id, entity_type, entity_id);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON audit_log
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

ALTER TABLE audit_log SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 80
);

GRANT SELECT, INSERT, DELETE ON audit_log TO cvert_ops_app;
