-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON scim_configs;
ALTER TABLE scim_configs DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_configs_token_hash_idx;
DROP TABLE IF EXISTS scim_configs;
