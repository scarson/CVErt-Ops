-- migrate:no-transaction
-- ABOUTME: Creates the organizations table (tenant containers).
-- ABOUTME: Global table — no RLS (orgs are the tenants, not org-scoped rows).

CREATE TABLE IF NOT EXISTS organizations (
    id          uuid        NOT NULL DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz NULL,
    CONSTRAINT organizations_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS organizations_name_idx
    ON organizations (name);

GRANT SELECT, INSERT, UPDATE ON organizations TO cvert_ops_app;
