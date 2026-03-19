-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS org_members_active_idx;
ALTER TABLE org_members DROP COLUMN IF EXISTS scim_exempt;
ALTER TABLE org_members DROP COLUMN IF EXISTS deactivated_at;
