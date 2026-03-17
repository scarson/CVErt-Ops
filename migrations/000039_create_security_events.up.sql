-- migrate:no-transaction
CREATE TABLE IF NOT EXISTS security_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    actor_ip    TEXT,
    actor_email TEXT,
    user_id     UUID,
    org_id      UUID,
    details     JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_created_at
    ON security_events (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_security_events_type_created
    ON security_events (event_type, created_at);
