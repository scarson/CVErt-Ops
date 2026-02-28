-- migrate:no-transaction
-- ABOUTME: Reverts RLS on org_invitations and removes the DELETE grant.
-- ABOUTME: Restores the state from migration 000009.

DROP POLICY IF EXISTS org_isolation ON org_invitations;
ALTER TABLE org_invitations DISABLE ROW LEVEL SECURITY;
REVOKE DELETE ON org_invitations FROM cvert_ops_app;
