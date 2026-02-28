-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

CREATE TABLE IF NOT EXISTS alert_rule_runs (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id              UUID        NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    org_id               UUID        NOT NULL,  -- denormalized for RLS
    path                 TEXT        NOT NULL CHECK (path IN ('realtime','batch','epss','activation')),
    status               TEXT        NOT NULL DEFAULT 'running'
                             CHECK (status IN ('running','complete','partial','error')),
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ NULL,
    candidates_evaluated INT         NOT NULL DEFAULT 0,
    matches_found        INT         NOT NULL DEFAULT 0,
    error_message        TEXT        NULL
);

ALTER TABLE alert_rule_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rule_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON alert_rule_runs
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- DELETE included: retention job hard-deletes old run rows by started_at.
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_rule_runs TO cvert_ops_app;

CREATE TABLE IF NOT EXISTS alert_events (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id           UUID        NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    -- Note: alert_rules uses soft-delete (deleted_at) -- the physical row is never removed,
    -- so ON DELETE CASCADE will not fire in normal operation. Alert event rows are
    -- intentionally retained after rule deletion for audit purposes (§21).
    org_id            UUID        NOT NULL,  -- denormalized for RLS
    -- No FK to cves: cves is a global table (cross-schema FK avoided).
    -- App validates CVE existence at evaluation time.
    cve_id            TEXT        NOT NULL,
    material_hash     TEXT        NOT NULL,
    last_match_state  BOOL        NOT NULL DEFAULT true,
    -- True for rows written by activation scan. Phase 3 delivery worker skips these
    -- rows to avoid firing notifications for historical matches.
    suppress_delivery BOOL        NOT NULL DEFAULT false,
    first_fired_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_fired_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    times_fired       INT         NOT NULL DEFAULT 1,
    -- Dedup constraint: exactly-once alerting across concurrent evaluation workers.
    -- All inserts use ON CONFLICT (org_id, rule_id, cve_id, material_hash) DO NOTHING RETURNING id.
    UNIQUE (org_id, rule_id, cve_id, material_hash)
);

ALTER TABLE alert_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_events FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON alert_events
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

-- DELETE included: retention job hard-deletes events older than 1 year (§21).
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_events TO cvert_ops_app;

-- alert_rule_runs indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_runs_org_id_idx
    ON alert_rule_runs (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_runs_rule_id_idx
    ON alert_rule_runs (rule_id);

-- Keyset pagination on (started_at DESC, id DESC). Also serves retention cleanup.
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rule_runs_started_at_idx
    ON alert_rule_runs (started_at);

-- alert_events indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_events_org_id_idx
    ON alert_events (org_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_events_rule_id_idx
    ON alert_events (rule_id);

-- Keyset pagination on (first_fired_at DESC, id DESC). Also serves 1-year retention cleanup.
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_events_first_fired_at_idx
    ON alert_events (first_fired_at);

-- GET /alert-events?cve_id= filter.
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_events_cve_id_idx
    ON alert_events (cve_id);

-- Resolution detection: find previously-matched events that may now resolve.
-- Query: WHERE rule_id = $1 AND org_id = $2 AND last_match_state = true
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_events_unresolved_idx
    ON alert_events (rule_id, org_id)
    WHERE last_match_state = true;
