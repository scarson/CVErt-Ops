-- ABOUTME: sqlc queries for SCIM config CRUD.
-- ABOUTME: Token lookup uses withBypassTx (pre-org-context auth). Config CRUD uses withOrgTx.

-- name: CreateSCIMConfig :one
INSERT INTO scim_configs (org_id, sso_connection_id, enabled, token_hash, token_prefix, default_role)
VALUES ($1, $2, $3, $4, $5, $6) RETURNING *;

-- name: GetSCIMConfigByOrgID :one
SELECT * FROM scim_configs WHERE org_id = $1;

-- name: GetSCIMConfigByTokenHash :one
SELECT * FROM scim_configs WHERE token_hash = $1;

-- name: GetSCIMConfigBySSOConnectionID :one
SELECT * FROM scim_configs WHERE sso_connection_id = $1;

-- name: UpdateSCIMConfig :exec
UPDATE scim_configs SET enabled = $2, default_role = $3, updated_at = now()
WHERE org_id = $1;

-- name: UpdateSCIMConfigToken :exec
UPDATE scim_configs SET token_hash = $2, token_prefix = $3, updated_at = now()
WHERE org_id = $1;

-- name: DeleteSCIMConfig :exec
DELETE FROM scim_configs WHERE org_id = $1;
