-- migrate:no-transaction

CREATE TABLE IF NOT EXISTS sso_connections (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    display_name      TEXT NOT NULL,
    issuer_url        TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    client_secret_enc BYTEA NOT NULL,
    scopes            TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    enabled           BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_connections_org_id_idx
    ON sso_connections (org_id);

ALTER TABLE sso_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_connections FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON sso_connections
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON sso_connections TO cvert_ops_app;

CREATE TABLE IF NOT EXISTS sso_email_domains (
    domain              TEXT PRIMARY KEY,
    sso_connection_id   UUID NOT NULL REFERENCES sso_connections(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_email_domains_connection_idx
    ON sso_email_domains (sso_connection_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS sso_email_domains_org_id_idx
    ON sso_email_domains (org_id);

ALTER TABLE sso_email_domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE sso_email_domains FORCE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON sso_email_domains
    USING (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid)
    WITH CHECK (current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid);

GRANT SELECT, INSERT, DELETE ON sso_email_domains TO cvert_ops_app;
