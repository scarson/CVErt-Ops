-- ABOUTME: sqlc queries for group management.
-- ABOUTME: All group operations are org-scoped via org_id parameter.

-- name: CreateGroup :one
INSERT INTO groups (org_id, name, description) VALUES ($1, $2, $3) RETURNING *;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL LIMIT 1;

-- name: ListOrgGroups :many
SELECT * FROM groups WHERE org_id = $1 AND deleted_at IS NULL ORDER BY name;

-- name: UpdateGroup :exec
UPDATE groups SET name = $3, description = $4 WHERE id = $1 AND org_id = $2;

-- name: SoftDeleteGroup :exec
UPDATE groups SET deleted_at = now() WHERE id = $1 AND org_id = $2;

-- name: AddGroupMember :exec
INSERT INTO group_members (org_id, group_id, user_id) VALUES ($1, $2, $3)
ON CONFLICT (group_id, user_id) DO NOTHING;

-- name: RemoveGroupMember :exec
DELETE FROM group_members WHERE group_id = $1 AND user_id = $2 AND org_id = $3;

-- name: ListGroupMembers :many
SELECT gm.*, u.email, u.display_name
FROM group_members gm JOIN users u ON u.id = gm.user_id
WHERE gm.group_id = $1 AND gm.org_id = $2
ORDER BY u.display_name;
