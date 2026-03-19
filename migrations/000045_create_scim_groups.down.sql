-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON scim_group_members;
ALTER TABLE scim_group_members DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_group_members_user_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_group_members_org_id_idx;
DROP TABLE IF EXISTS scim_group_members;

DROP POLICY IF EXISTS org_isolation ON scim_groups;
ALTER TABLE scim_groups DISABLE ROW LEVEL SECURITY;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_mapped_group_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_org_external_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS scim_groups_org_id_idx;
DROP TABLE IF EXISTS scim_groups;
