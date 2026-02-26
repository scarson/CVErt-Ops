-- migrate:no-transaction
-- ABOUTME: Creates users and user_identities tables.
-- ABOUTME: Global tables — no RLS (not org-scoped).

CREATE TABLE users (
    id                    uuid        NOT NULL DEFAULT gen_random_uuid(),
    email                 text        NOT NULL,
    display_name          text        NOT NULL DEFAULT '',
    password_hash         text        NULL,     -- NULL for OAuth-only accounts
    password_hash_version int         NOT NULL DEFAULT 2, -- 2=argon2id
    token_version         int         NOT NULL DEFAULT 1,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_login_at         timestamptz NULL,
    CONSTRAINT users_pkey PRIMARY KEY (id)
);

-- Unique email index (partial: excludes deleted users if soft-delete is added later).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_email_uq ON users (email);

-- user_identities links users to OAuth providers (or native auth).
-- Matched on (provider, provider_user_id) — NEVER by email alone.
CREATE TABLE user_identities (
    id               uuid        NOT NULL DEFAULT gen_random_uuid(),
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider         text        NOT NULL,  -- 'github', 'google', 'native'
    provider_user_id text        NOT NULL,  -- immutable: GitHub numeric ID, Google sub
    email            text        NOT NULL,  -- mutable display attribute only
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT user_identities_pkey PRIMARY KEY (id)
);

-- The authoritative identity key: (provider, provider_user_id).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS user_identities_provider_uq
    ON user_identities (provider, provider_user_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS user_identities_user_idx
    ON user_identities (user_id);

GRANT SELECT, INSERT, UPDATE ON users TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_identities TO cvert_ops_app;
