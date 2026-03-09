-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS password_reset_tokens_hash_idx;
DROP INDEX CONCURRENTLY IF EXISTS password_reset_tokens_user_idx;
DROP TABLE IF EXISTS password_reset_tokens;
