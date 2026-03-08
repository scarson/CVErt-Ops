-- migrate:no-transaction
-- ABOUTME: Creates password_reset_tokens for secure password recovery flow.
-- ABOUTME: Global table — no RLS (not org-scoped). Tokens stored as SHA-256 hash.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS password_reset_tokens_user_idx
    ON password_reset_tokens (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS password_reset_tokens_hash_idx
    ON password_reset_tokens (token_hash);

GRANT SELECT, INSERT, UPDATE, DELETE ON password_reset_tokens TO cvert_ops_app;
