-- migrate:no-transaction
-- ABOUTME: Enables RLS on org_invitations and adds the missing DELETE grant.
-- ABOUTME: Admin endpoints use withOrgTx and public token-lookup uses withBypassTx.

-- GRANT DELETE was omitted from migration 000009 and CancelInvitation executes DELETE.
GRANT DELETE ON org_invitations TO cvert_ops_app;

ALTER TABLE org_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_invitations FORCE ROW LEVEL SECURITY;

-- Standard dual-escape policy: bypass_rls for worker paths and org_id match for app paths.
-- GetInvitationByToken uses withBypassTx (no org context at public or accept endpoints).
-- CreateOrgInvitation and ListOrgInvitations and CancelInvitation use withOrgTx.
CREATE POLICY org_isolation ON org_invitations
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );
