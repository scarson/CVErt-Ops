-- migrate:no-transaction
-- ABOUTME: Creates the refresh_tokens table for stateful JTI-based token tracking.
-- ABOUTME: Enables theft detection via the reuse + grace-window pattern (PLAN.md §7.1).

CREATE TABLE refresh_tokens (
    jti              uuid        NOT NULL,
    user_id          uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_version    int         NOT NULL,   -- must match users.token_version at validation
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz NULL,       -- non-null = already consumed
    replaced_by_jti  uuid        NULL REFERENCES refresh_tokens(jti),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT refresh_tokens_pkey PRIMARY KEY (jti)
);

-- For cleanup and per-user lookup.
CREATE INDEX CONCURRENTLY IF NOT EXISTS refresh_tokens_user_idx
    ON refresh_tokens (user_id, expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO cvert_ops_app;
