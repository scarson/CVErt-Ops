-- migrate:no-transaction
-- ABOUTME: Drops group_members table and RLS policies.
-- ABOUTME: Down migration for 000011_create_group_members.

DROP POLICY IF EXISTS org_isolation ON group_members;
ALTER TABLE IF EXISTS group_members DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS group_members_org_idx;
DROP INDEX CONCURRENTLY IF EXISTS group_members_group_idx;
DROP TABLE IF EXISTS group_members;
