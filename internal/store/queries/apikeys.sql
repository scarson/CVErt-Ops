-- ABOUTME: sqlc queries for API key management.
-- ABOUTME: LookupAPIKey is used in authentication hot-path; does not take orgID.

-- name: CreateAPIKey :one
INSERT INTO api_keys (org_id, created_by_user_id, key_hash, name, role, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: LookupAPIKey :one
-- Used for authentication — checks revocation + expiry. Caller validates org membership.
SELECT * FROM api_keys
WHERE key_hash = $1
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > now())
LIMIT 1;

-- name: ListOrgAPIKeys :many
SELECT id, name, role, expires_at, last_used_at, created_at, revoked_at
FROM api_keys
WHERE org_id = $1
ORDER BY created_at DESC;

-- name: RevokeAPIKey :exec
UPDATE api_keys SET revoked_at = now()
WHERE id = $1 AND org_id = $2;

-- name: UpdateAPIKeyLastUsed :exec
UPDATE api_keys SET last_used_at = now() WHERE id = $1;
