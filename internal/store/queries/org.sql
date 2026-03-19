-- ABOUTME: sqlc queries for organization and membership management.
-- ABOUTME: Org-scoped methods take org_id as a parameter (Layer 1 isolation).

-- name: CreateOrg :one
INSERT INTO organizations (name) VALUES ($1) RETURNING *;

-- name: UpdateOrg :one
UPDATE organizations SET name = $2 WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: GetOrgByID :one
SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL LIMIT 1;

-- name: CreateOrgMember :exec
INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO NOTHING;

-- name: GetOrgMemberRole :one
SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2 LIMIT 1;

-- name: GetOrgMemberRoleAndStatus :one
SELECT role, deactivated_at FROM org_members WHERE org_id = $1 AND user_id = $2 LIMIT 1;

-- name: ListOrgMembers :many
SELECT om.*, u.email, u.display_name FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1
ORDER BY om.created_at;

-- name: UpdateOrgMemberRole :exec
UPDATE org_members SET role = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: DeleteOrgMember :exec
DELETE FROM org_members WHERE org_id = $1 AND user_id = $2;

-- name: ListUserOrgs :many
SELECT om.org_id, om.role, o.name FROM org_members om
JOIN organizations o ON o.id = om.org_id
WHERE om.user_id = $1 AND o.deleted_at IS NULL
ORDER BY o.name;

-- name: GetOrgOwnerCount :one
SELECT COUNT(*) FROM org_members WHERE org_id = $1 AND role = 'owner';

-- name: CreateOrgInvitation :one
INSERT INTO org_invitations (org_id, email, role, token, created_by, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetOrgInvitationByID :one
SELECT * FROM org_invitations WHERE id = $1 AND org_id = $2 LIMIT 1;

-- name: GetInvitationByToken :one
SELECT * FROM org_invitations WHERE token = $1 LIMIT 1;

-- name: AcceptInvitation :exec
UPDATE org_invitations SET accepted_at = COALESCE(accepted_at, now()) WHERE id = $1;

-- name: ListOrgInvitations :many
SELECT * FROM org_invitations
WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: DeleteOrgInvitation :execresult
DELETE FROM org_invitations WHERE id = $1 AND org_id = $2;

-- name: GetPendingInvitationByEmail :one
SELECT id FROM org_invitations
WHERE org_id = $1 AND lower(email) = lower(@email) AND accepted_at IS NULL AND expires_at > now()
LIMIT 1;

-- name: GetOrgTier :one
SELECT tier, tier_overrides FROM organizations WHERE id = $1;

-- name: UpdateOrgTier :exec
UPDATE organizations SET tier = $2 WHERE id = $1;

-- name: UpdateOrgMFASettings :one
UPDATE organizations SET
    mfa_required_all = $2,
    mfa_remember_device_allowed = $3,
    mfa_remember_device_days = $4
WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: CountAlertRulesByOrg :one
SELECT COUNT(*) FROM alert_rules WHERE org_id = $1 AND deleted_at IS NULL;

-- name: CountWatchlistsByOrg :one
SELECT COUNT(*) FROM watchlists WHERE org_id = $1 AND deleted_at IS NULL;

-- name: CountMembersByOrg :one
SELECT COUNT(*) FROM org_members WHERE org_id = $1;

-- name: CountMemberSlotsUsedByOrg :one
SELECT CAST(
    (SELECT COUNT(*) FROM org_members m WHERE m.org_id = $1)
  + (SELECT COUNT(*) FROM org_invitations i WHERE i.org_id = $1 AND i.accepted_at IS NULL AND i.expires_at > now())
AS bigint);

-- name: ListAllOrgs :many
SELECT id, tier, tier_overrides FROM organizations
WHERE deleted_at IS NULL;

-- name: DeactivateOrgMember :exec
UPDATE org_members SET deactivated_at = now(), updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: ReactivateOrgMember :exec
UPDATE org_members SET deactivated_at = NULL, updated_at = now()
WHERE org_id = $1 AND user_id = $2;

-- name: GetOrgMemberFull :one
SELECT om.org_id, om.user_id, om.role, om.created_at, om.updated_at,
       om.deactivated_at, om.scim_exempt,
       u.email, u.display_name
FROM org_members om
JOIN users u ON u.id = om.user_id
WHERE om.org_id = $1 AND om.user_id = $2;

-- name: CountActiveOrgMembers :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND deactivated_at IS NULL;

-- name: CountActiveOrgOwners :one
SELECT COUNT(*)::int FROM org_members
WHERE org_id = $1 AND role = 'owner' AND deactivated_at IS NULL;

-- name: UpdateOrgMemberSCIMExempt :exec
UPDATE org_members SET scim_exempt = $3, updated_at = now()
WHERE org_id = $1 AND user_id = $2;
