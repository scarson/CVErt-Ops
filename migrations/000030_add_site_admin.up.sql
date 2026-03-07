ALTER TABLE users ADD COLUMN is_site_admin boolean NOT NULL DEFAULT false;

-- Enforce at most one site admin at the database level.
-- Prevents race condition when two users register simultaneously.
CREATE UNIQUE INDEX users_single_site_admin ON users ((true)) WHERE is_site_admin = true;
