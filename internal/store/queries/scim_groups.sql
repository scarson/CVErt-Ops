-- ABOUTME: sqlc queries for SCIM group and membership management.
-- ABOUTME: All queries are org-scoped via RLS. scim_group_members denormalize org_id.

-- name: CreateSCIMGroup :one
INSERT INTO scim_groups (org_id, external_id, display_name)
VALUES ($1, $2, $3) RETURNING *;

-- name: GetSCIMGroupByID :one
SELECT * FROM scim_groups WHERE id = $1;

-- name: GetSCIMGroupByDisplayName :one
SELECT * FROM scim_groups WHERE org_id = $1 AND display_name = $2;

-- name: GetSCIMGroupByExternalID :one
SELECT * FROM scim_groups WHERE org_id = $1 AND external_id = $2;

-- name: ListSCIMGroups :many
SELECT sg.*, COUNT(sgm.user_id)::int AS member_count
FROM scim_groups sg
LEFT JOIN scim_group_members sgm ON sgm.scim_group_id = sg.id
WHERE sg.org_id = $1
GROUP BY sg.id
ORDER BY sg.display_name;

-- name: UpdateSCIMGroup :exec
UPDATE scim_groups SET display_name = $2, external_id = $3, updated_at = now()
WHERE id = $1;

-- name: UpdateSCIMGroupMapping :exec
UPDATE scim_groups SET mapped_role = $2, mapped_group_id = $3, updated_at = now()
WHERE id = $1;

-- name: DeleteSCIMGroup :exec
DELETE FROM scim_groups WHERE id = $1;

-- name: AddSCIMGroupMember :exec
INSERT INTO scim_group_members (scim_group_id, user_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (scim_group_id, user_id) DO NOTHING;

-- name: RemoveSCIMGroupMember :exec
DELETE FROM scim_group_members WHERE scim_group_id = $1 AND user_id = $2;

-- name: ListSCIMGroupMembers :many
SELECT user_id FROM scim_group_members WHERE scim_group_id = $1;

-- name: ListUserSCIMGroups :many
SELECT sg.* FROM scim_groups sg
JOIN scim_group_members sgm ON sgm.scim_group_id = sg.id
WHERE sgm.user_id = $1 AND sg.org_id = $2;

-- name: SetSCIMGroupMembers_Delete :exec
DELETE FROM scim_group_members WHERE scim_group_id = $1;

-- name: CountOtherSCIMGroupsWithSameMapping :one
SELECT COUNT(*)::int FROM scim_group_members sgm
JOIN scim_groups sg ON sgm.scim_group_id = sg.id
WHERE sgm.user_id = $1
  AND sg.mapped_group_id = $2
  AND sg.id != $3;
