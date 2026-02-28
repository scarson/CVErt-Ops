-- migrate:no-transaction
-- ABOUTME: Drops org_invitations table.
-- ABOUTME: Down migration for 000009_create_org_invitations.

DROP INDEX CONCURRENTLY IF EXISTS org_invitations_token_uq;
DROP INDEX CONCURRENTLY IF EXISTS org_invitations_org_idx;
DROP TABLE IF EXISTS org_invitations;
