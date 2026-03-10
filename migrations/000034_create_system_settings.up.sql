-- system_settings stores system-level key-value configuration and sentinels.
-- Not org-scoped: no RLS policy. Accessed only by site admins and CLI tools.
CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT        PRIMARY KEY,
    value      BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
