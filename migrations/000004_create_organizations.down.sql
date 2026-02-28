-- migrate:no-transaction
-- ABOUTME: Drops the organizations table.
-- ABOUTME: Down migration for 000004_create_organizations.

DROP INDEX CONCURRENTLY IF EXISTS organizations_name_idx;
DROP TABLE IF EXISTS organizations;
