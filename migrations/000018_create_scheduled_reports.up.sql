-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block.

-- ── scheduled_reports ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scheduled_reports (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                TEXT        NOT NULL CHECK (char_length(name) <= 255),
    scheduled_time      TIME        NOT NULL,
    timezone            TEXT        NOT NULL DEFAULT 'UTC' CHECK (char_length(timezone) <= 40),
    next_run_at         TIMESTAMPTZ NOT NULL,
    last_run_at         TIMESTAMPTZ NULL,
    severity_threshold  TEXT        NULL CHECK (severity_threshold IN ('critical','high','medium','low')),
    -- Deleted watchlist IDs silently match nothing (app-layer validation; FK impossible on arrays).
    watchlist_ids       UUID[]      NULL,
    send_on_empty       BOOLEAN     NOT NULL DEFAULT TRUE,
    ai_summary          BOOLEAN     NOT NULL DEFAULT FALSE,
    status              TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
    deleted_at          TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scheduled_reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_reports FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON scheduled_reports
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Soft-delete entity: no DELETE grant.
GRANT SELECT, INSERT, UPDATE ON scheduled_reports TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_org_id_idx
    ON scheduled_reports (org_id);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_name_uq
    ON scheduled_reports (org_id, name) WHERE deleted_at IS NULL;

-- Scheduler poll: find due reports.
CREATE INDEX CONCURRENTLY IF NOT EXISTS scheduled_reports_next_run_idx
    ON scheduled_reports (next_run_at)
    WHERE status = 'active' AND deleted_at IS NULL;

-- ── report_channels (M:M binding) ─────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS report_channels (
    report_id  UUID        NOT NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE,
    channel_id UUID        NOT NULL REFERENCES notification_channels(id) ON DELETE RESTRICT,
    org_id     UUID        NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, channel_id)
);

ALTER TABLE report_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON report_channels
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- Hard-delete join table: no UPDATE grant.
GRANT SELECT, INSERT, DELETE ON report_channels TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS report_channels_org_id_idx
    ON report_channels (org_id);

-- Channel deletion pre-flight: "which reports reference this channel?"
CREATE INDEX CONCURRENTLY IF NOT EXISTS report_channels_channel_id_idx
    ON report_channels (channel_id);
