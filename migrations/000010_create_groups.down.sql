-- migrate:no-transaction
-- ABOUTME: Drops the groups table and RLS policies.
-- ABOUTME: Down migration for 000010_create_groups.

DROP POLICY IF EXISTS org_isolation ON groups;
ALTER TABLE IF EXISTS groups DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS groups_name_uq;
DROP INDEX CONCURRENTLY IF EXISTS groups_org_idx;
DROP TABLE IF EXISTS groups;
