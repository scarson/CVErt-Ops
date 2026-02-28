-- migrate:no-transaction
-- ABOUTME: Drops users and user_identities tables.
-- ABOUTME: Down migration for 000005_create_users.

DROP INDEX CONCURRENTLY IF EXISTS user_identities_provider_uq;
DROP INDEX CONCURRENTLY IF EXISTS user_identities_user_idx;
DROP TABLE IF EXISTS user_identities;
DROP INDEX CONCURRENTLY IF EXISTS users_email_uq;
DROP TABLE IF EXISTS users;
