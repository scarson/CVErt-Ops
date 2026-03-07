DROP INDEX IF EXISTS users_single_site_admin;
ALTER TABLE users DROP COLUMN is_site_admin;
