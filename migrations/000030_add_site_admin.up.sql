-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall §11.2).

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_site_admin boolean NOT NULL DEFAULT false;

-- Enforce at most one site admin at the database level.
-- Prevents race condition when two users register simultaneously.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_single_site_admin ON users ((true)) WHERE is_site_admin = true;
