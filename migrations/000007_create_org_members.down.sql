-- migrate:no-transaction
-- ABOUTME: Drops org_members table and RLS policies.
-- ABOUTME: Down migration for 000007_create_org_members.

DROP POLICY IF EXISTS org_isolation ON org_members;
ALTER TABLE IF EXISTS org_members DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS org_members_org_idx;
DROP INDEX CONCURRENTLY IF EXISTS org_members_user_idx;
DROP TABLE IF EXISTS org_members;
