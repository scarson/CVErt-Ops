-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS email_verification_tokens_hash_idx;
DROP INDEX CONCURRENTLY IF EXISTS email_verification_tokens_user_idx;
DROP TABLE IF EXISTS email_verification_tokens;
