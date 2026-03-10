-- ABOUTME: sqlc queries for site admin organization management.
-- ABOUTME: All queries run via withBypassTx (admin is not a member of target orgs).

-- name: AdminGetOrgByID :one
SELECT * FROM organizations WHERE id = $1;

-- name: AdminUpdateOrgTier :one
UPDATE organizations SET tier = $2 WHERE id = $1 AND deleted_at IS NULL
RETURNING *;

-- name: AdminSuspendOrg :one
UPDATE organizations SET suspended_at = now() WHERE id = $1 AND deleted_at IS NULL AND suspended_at IS NULL
RETURNING *;

-- name: AdminUnsuspendOrg :one
UPDATE organizations SET suspended_at = NULL WHERE id = $1 AND deleted_at IS NULL AND suspended_at IS NOT NULL
RETURNING *;

-- name: AdminCountOrgAlertRules :one
SELECT COUNT(*) FROM alert_rules WHERE org_id = $1 AND deleted_at IS NULL;

-- name: AdminCountOrgWatchlists :one
SELECT COUNT(*) FROM watchlists WHERE org_id = $1 AND deleted_at IS NULL;

-- name: AdminCountOrgMembers :one
SELECT COUNT(*) FROM org_members WHERE org_id = $1;

-- name: AdminCountOrgChannels :one
SELECT COUNT(*) FROM notification_channels WHERE org_id = $1 AND deleted_at IS NULL;
