-- ABOUTME: sqlc queries for user authentication operations.
-- ABOUTME: Used by store/auth.go — static CRUD only. No RLS (users is global table).

-- name: CreateUser :one
INSERT INTO users (email, display_name, password_hash, password_hash_version)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1 LIMIT 1;

-- name: UpdateLastLogin :exec
UPDATE users SET last_login_at = now() WHERE id = $1;

-- name: IncrementTokenVersion :one
UPDATE users SET token_version = token_version + 1 WHERE id = $1
RETURNING token_version;

-- name: UpdatePasswordHash :exec
UPDATE users
SET password_hash = $2, password_hash_version = $3, token_version = token_version + 1
WHERE id = $1;

-- name: UpsertUserIdentity :exec
INSERT INTO user_identities (user_id, provider, provider_user_id, email)
VALUES ($1, $2, $3, $4)
ON CONFLICT (provider, provider_user_id)
DO UPDATE SET email = EXCLUDED.email;

-- name: GetUserByProviderID :one
SELECT u.* FROM users u
JOIN user_identities ui ON ui.user_id = u.id
WHERE ui.provider = $1 AND ui.provider_user_id = $2
LIMIT 1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (jti, user_id, token_version, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE jti = $1 LIMIT 1;

-- name: MarkRefreshTokenUsed :exec
UPDATE refresh_tokens
SET used_at = now(), replaced_by_jti = $2
WHERE jti = $1;

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM refresh_tokens
WHERE expires_at < now() - interval '60 seconds';
