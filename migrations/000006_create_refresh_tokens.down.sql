-- migrate:no-transaction
-- ABOUTME: Drops the refresh_tokens table.
-- ABOUTME: Down migration for 000006_create_refresh_tokens.

DROP INDEX CONCURRENTLY IF EXISTS refresh_tokens_user_idx;
DROP TABLE IF EXISTS refresh_tokens;
