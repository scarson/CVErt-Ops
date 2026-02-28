-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

CREATE TYPE watchlist_item_type AS ENUM ('package', 'cpe');

CREATE TABLE IF NOT EXISTS watchlists (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id    UUID        NULL     REFERENCES groups(id)        ON DELETE SET NULL,
    name        TEXT        NOT NULL CHECK (char_length(name) <= 255),
    description TEXT        NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at  TIMESTAMPTZ NULL
);

ALTER TABLE watchlists ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlists FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON watchlists
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE ON watchlists TO cvert_ops_app;

CREATE TABLE IF NOT EXISTS watchlist_items (
    id             UUID                  PRIMARY KEY DEFAULT gen_random_uuid(),
    watchlist_id   UUID                  NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    org_id         UUID                  NOT NULL,  -- denormalized for RLS (no FK on denormalized column)
    item_type      watchlist_item_type   NOT NULL,
    -- package fields (required when item_type = 'package')
    ecosystem      TEXT                  NULL CHECK (char_length(ecosystem) <= 64),
    package_name   TEXT                  NULL CHECK (char_length(package_name) <= 255),
    namespace      TEXT                  NULL CHECK (char_length(namespace) <= 255),
    -- cpe fields (required when item_type = 'cpe')
    cpe_normalized TEXT                  NULL CHECK (char_length(cpe_normalized) <= 512),
    -- type-guard constraints: required fields per item_type
    CONSTRAINT wi_package_fields CHECK (
        item_type != 'package' OR (ecosystem IS NOT NULL AND package_name IS NOT NULL)
    ),
    CONSTRAINT wi_cpe_fields CHECK (
        item_type != 'cpe' OR cpe_normalized IS NOT NULL
    ),
    created_at     TIMESTAMPTZ           NOT NULL DEFAULT now(),
    deleted_at     TIMESTAMPTZ           NULL
);

ALTER TABLE watchlist_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_items FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON watchlist_items
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, UPDATE ON watchlist_items TO cvert_ops_app;

-- watchlists indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlists_org_id_idx
    ON watchlists (org_id);

-- Supports queries filtering by group (nullable FK).
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlists_group_id_idx
    ON watchlists (group_id)
    WHERE group_id IS NOT NULL;

-- Keyset pagination on (created_at DESC, id DESC). Also serves retention queries.
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlists_created_at_idx
    ON watchlists (created_at);

-- Partial unique: name must be unique among live watchlists in an org.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS watchlists_name_uq
    ON watchlists (org_id, name)
    WHERE deleted_at IS NULL;

-- watchlist_items indexes
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_org_id_idx
    ON watchlist_items (org_id);

-- List all items for a watchlist (all types, includes soft-deleted for admin views).
CREATE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_watchlist_id_idx
    ON watchlist_items (watchlist_id);

-- Partial unique: one active package entry per (watchlist, ecosystem, package_name).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_pkg_uq
    ON watchlist_items (watchlist_id, ecosystem, package_name)
    WHERE item_type = 'package' AND deleted_at IS NULL;

-- Partial unique: one active CPE entry per (watchlist, cpe_normalized).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS watchlist_items_cpe_uq
    ON watchlist_items (watchlist_id, cpe_normalized)
    WHERE item_type = 'cpe' AND deleted_at IS NULL;
