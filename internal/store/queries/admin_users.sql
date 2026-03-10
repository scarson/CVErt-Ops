-- ABOUTME: sqlc queries for site admin user management.
-- ABOUTME: All queries run via withBypassTx (admin operates across all orgs).

-- name: AdminGetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: AdminDisableUser :one
UPDATE users SET disabled_at = now() WHERE id = $1 AND disabled_at IS NULL
RETURNING *;

-- name: AdminEnableUser :one
UPDATE users SET disabled_at = NULL WHERE id = $1 AND disabled_at IS NOT NULL
RETURNING *;

-- name: AdminUnlockUser :one
UPDATE users SET locked_at = NULL, failed_login_count = 0 WHERE id = $1 AND locked_at IS NOT NULL
RETURNING *;

-- name: AdminForcePasswordReset :one
UPDATE users SET force_password_reset = true WHERE id = $1 AND force_password_reset = false
RETURNING *;
