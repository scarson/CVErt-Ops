-- migrate:no-transaction
-- ABOUTME: Creates org_invitations for email-based member invitation flow.
-- ABOUTME: No RLS — accept endpoint is public; admin endpoints enforce RBAC at handler level.

CREATE TABLE org_invitations (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email       text        NOT NULL,
    role        text        NOT NULL DEFAULT 'member',
    token       text        NOT NULL,           -- 32 random bytes, hex-encoded; used in link
    created_by  uuid        NOT NULL REFERENCES users(id),
    expires_at  timestamptz NOT NULL,
    accepted_at timestamptz NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT org_invitations_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS org_invitations_token_uq ON org_invitations (token);
CREATE INDEX CONCURRENTLY IF NOT EXISTS org_invitations_org_idx ON org_invitations (org_id);

GRANT SELECT, INSERT, UPDATE ON org_invitations TO cvert_ops_app;
