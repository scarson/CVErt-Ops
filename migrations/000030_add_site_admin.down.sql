-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS users_single_site_admin;
ALTER TABLE users DROP COLUMN IF EXISTS is_site_admin;
