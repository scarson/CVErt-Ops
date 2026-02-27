-- migrate:no-transaction
-- ABOUTME: Creates api_keys table for machine-to-machine authentication.
-- ABOUTME: Stores only sha256(raw_key) — never the raw key. RLS on org_id.

CREATE TABLE IF NOT EXISTS api_keys (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id              uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by_user_id  uuid        NOT NULL REFERENCES users(id),
    key_hash            text        NOT NULL,   -- sha256(raw_key), hex-encoded
    name                text        NOT NULL,   -- user-visible label
    role                text        NOT NULL,   -- role ≤ creator's role at time of creation
    expires_at          timestamptz NULL,       -- NULL = never expires
    last_used_at        timestamptz NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz NULL,
    CONSTRAINT api_keys_pkey PRIMARY KEY (id)
);

-- O(1) lookup by hash. No prefix stored — hash is sufficient with UNIQUE index.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS api_keys_hash_uq ON api_keys (key_hash);
CREATE INDEX CONCURRENTLY IF NOT EXISTS api_keys_org_idx ON api_keys (org_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON api_keys TO cvert_ops_app;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON api_keys
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
