-- ABOUTME: sqlc queries for MFA credential management.
-- ABOUTME: Used by store/mfa.go — global tables, no RLS.

-- name: GetMFACredentialsByUserID :many
SELECT * FROM mfa_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: GetMFACredentialByUserAndMethod :one
SELECT * FROM mfa_credentials WHERE user_id = $1 AND method = $2;

-- name: CreateMFACredential :one
INSERT INTO mfa_credentials (user_id, method, secret_enc)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateMFACredentialLastUsed :exec
UPDATE mfa_credentials
SET last_used_step = $2, last_used_at = now()
WHERE id = $1;

-- name: DeleteMFACredential :execrows
DELETE FROM mfa_credentials WHERE user_id = $1 AND method = $2;

-- name: DeleteAllMFACredentials :execrows
DELETE FROM mfa_credentials WHERE user_id = $1;

-- name: UserHasMFACredentials :one
SELECT EXISTS(SELECT 1 FROM mfa_credentials WHERE user_id = $1) AS has_mfa;

-- name: CountMFACredentialsByUser :one
SELECT COUNT(*) FROM mfa_credentials WHERE user_id = $1;
