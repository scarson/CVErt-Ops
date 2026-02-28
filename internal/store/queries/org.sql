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
INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3);

-- name: GetOrgMemberRole :one
SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2 LIMIT 1;

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

-- name: GetInvitationByToken :one
SELECT * FROM org_invitations WHERE token = $1 LIMIT 1;

-- name: AcceptInvitation :exec
UPDATE org_invitations SET accepted_at = now() WHERE id = $1;

-- name: ListOrgInvitations :many
SELECT * FROM org_invitations
WHERE org_id = $1 AND accepted_at IS NULL AND expires_at > now()
ORDER BY created_at DESC;

-- name: DeleteOrgInvitation :exec
DELETE FROM org_invitations WHERE id = $1 AND org_id = $2;
