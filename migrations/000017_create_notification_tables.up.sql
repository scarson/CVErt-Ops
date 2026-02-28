-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

CREATE TABLE IF NOT EXISTS notification_channels (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                     TEXT        NOT NULL CHECK (char_length(name) <= 255),
    type                     TEXT        NOT NULL CHECK (type IN ('webhook')),
    config                   JSONB       NOT NULL DEFAULT '{}',
    CONSTRAINT nc_webhook_url CHECK (type != 'webhook' OR jsonb_exists(config, 'url')),
    -- Server-generated 256-bit random secret. Never returned in GET responses.
    signing_secret           TEXT        NOT NULL,
    -- Populated during rotation -- cleared after grace period via clear-secondary endpoint.
    signing_secret_secondary TEXT        NULL,
    deleted_at               TIMESTAMPTZ NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notification_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Soft-delete: no DELETE grant.
GRANT SELECT, INSERT, UPDATE ON notification_channels TO cvert_ops_app;

-- alert_rule_channels: M:M binding of alert rules to notification channels.
-- Hard-delete: bindings have no independent identity.
-- org_id denormalized for RLS (no FK — established pattern, see watchlist_items).
-- rule_id CASCADE: binding deleted when rule is deleted.
-- channel_id RESTRICT: last-resort guard against hard-deleting a soft-delete entity.
CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id    UUID        NOT NULL REFERENCES alert_rules(id)            ON DELETE CASCADE,
    channel_id UUID        NOT NULL REFERENCES notification_channels(id)  ON DELETE RESTRICT,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, channel_id)
);

ALTER TABLE alert_rule_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rule_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON alert_rule_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Hard-delete join table: no UPDATE grant.
GRANT SELECT, INSERT, DELETE ON alert_rule_channels TO cvert_ops_app;

-- notification_deliveries: delivery job queue.
-- Debounce: one pending row per (rule, channel) -- CVE snapshots accumulate in payload.
-- rule_id has no FK: historical reference -- alert_rules uses soft-delete.
-- Retention: 90 days per §21.2.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID        NOT NULL,
    -- No FK: historical reference preserved after rule soft-deletion.
    rule_id           UUID        NOT NULL,
    channel_id        UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    status            TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','processing','succeeded','failed','cancelled')),
    attempt_count     INT         NOT NULL DEFAULT 0,
    -- JSONB array of CVE snapshots accumulated during the debounce window.
    payload           JSONB       NOT NULL DEFAULT '[]',
    -- Dual-purpose: debounce window end and retry backoff next-attempt time.
    send_after        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_attempted_at TIMESTAMPTZ NULL,
    delivered_at      TIMESTAMPTZ NULL,
    last_error        TEXT        NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON notification_deliveries
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- DELETE included: retention job hard-deletes rows older than 90 days (§21.2).
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_deliveries TO cvert_ops_app;

-- High-churn: INSERT + 2 UPDATEs (claim → processing → succeeded/failed) per delivery.
ALTER TABLE notification_deliveries SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 70
);

-- ── notification_channels indexes ────────────────────────────────────────────

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_org_id_idx
    ON notification_channels (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_active_idx
    ON notification_channels (org_id) WHERE deleted_at IS NULL;

-- Partial unique: name unique among live channels in an org.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS notification_channels_name_uq
    ON notification_channels (org_id, name) WHERE deleted_at IS NULL;

-- ── alert_rule_channels indexes ──────────────────────────────────────────────

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_channels_org_id_idx
    ON alert_rule_channels (org_id);

-- Channel deletion pre-flight: "which rules reference this channel?"
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_channels_channel_id_idx
    ON alert_rule_channels (channel_id);

-- ── notification_deliveries indexes ──────────────────────────────────────────

-- At most one pending delivery per (rule, channel). Debounce ON CONFLICT target.
-- Deviation from PLAN.md per-event idempotency key: debounce groups N events into
-- one row, making a per-event key incorrect.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_notification_deliveries_pending
    ON notification_deliveries (rule_id, channel_id) WHERE status = 'pending';

-- Delivery worker claim query.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_claim_idx
    ON notification_deliveries (send_after) WHERE status = 'pending';

-- Per-org concurrency cap: count in-flight deliveries per org.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_processing_idx
    ON notification_deliveries (org_id) WHERE status = 'processing';

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_org_id_idx
    ON notification_deliveries (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_channel_id_idx
    ON notification_deliveries (channel_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_rule_id_idx
    ON notification_deliveries (rule_id);

-- §21.3 explicit requirement: retention cleanup batches by created_at.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_created_at_idx
    ON notification_deliveries (created_at);
