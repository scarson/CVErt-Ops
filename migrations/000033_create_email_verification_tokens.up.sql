-- migrate:no-transaction
-- ABOUTME: Creates email_verification_tokens for email ownership verification.
-- ABOUTME: Global table — no RLS. Tokens stored as SHA-256 hash.

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT email_verification_tokens_pkey PRIMARY KEY (id)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS email_verification_tokens_user_idx
    ON email_verification_tokens (user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS email_verification_tokens_hash_idx
    ON email_verification_tokens (token_hash);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_verification_tokens TO cvert_ops_app;
