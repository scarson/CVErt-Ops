-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

CREATE TABLE IF NOT EXISTS alert_rules (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                        TEXT        NOT NULL CHECK (char_length(name) <= 255),
    logic                       TEXT        NOT NULL CHECK (logic IN ('and', 'or')),
    conditions                  JSONB       NOT NULL,
    -- No FK on uuid[] -- app validates all IDs belong to this org at save time.
    -- Deleted watchlist IDs silently match nothing at evaluation time
    -- (evaluator's EXISTS subquery filters wi.deleted_at IS NULL).
    watchlist_ids               UUID[]      NULL,
    dsl_version                 INT         NOT NULL DEFAULT 1,
    -- Set by DSL compiler at save time. Used to route evaluation paths.
    has_epss_condition          BOOL        NOT NULL DEFAULT false,
    is_epss_only                BOOL        NOT NULL DEFAULT false,
    status                      TEXT        NOT NULL DEFAULT 'draft'
                                    CHECK (status IN ('draft','activating','active','error','disabled')),
    fire_on_non_material_changes BOOL       NOT NULL DEFAULT false,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at                  TIMESTAMPTZ NULL
);

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON alert_rules
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE ON alert_rules TO cvert_ops_app;

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_org_id_idx
    ON alert_rules (org_id);

-- Evaluator polling: load all active/activating rules for an org.
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_active_idx
    ON alert_rules (org_id)
    WHERE status IN ('active', 'activating') AND deleted_at IS NULL;

-- Keyset pagination on (created_at DESC, id DESC).
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_created_at_idx
    ON alert_rules (created_at);

-- Partial unique: name must be unique among live rules in an org.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_name_uq
    ON alert_rules (org_id, name)
    WHERE deleted_at IS NULL;

-- Retention cleanup: find old soft-deleted rows.
CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_deleted_at_idx
    ON alert_rules (deleted_at)
    WHERE deleted_at IS NOT NULL;
