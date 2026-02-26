-- migrate:no-transaction
-- ABOUTME: Drops api_keys table and RLS policies.
-- ABOUTME: Down migration for 000008_create_api_keys.

DROP POLICY IF EXISTS org_isolation ON api_keys;
ALTER TABLE IF EXISTS api_keys DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS api_keys_hash_uq;
DROP INDEX CONCURRENTLY IF EXISTS api_keys_org_idx;
DROP TABLE IF EXISTS api_keys;
