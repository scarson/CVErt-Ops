-- ABOUTME: sqlc queries for password reset token operations.
-- ABOUTME: Used by store/password_reset.go — global table, no RLS.

-- name: CreatePasswordResetToken :exec
INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
VALUES ($1, $2, $3);

-- name: GetPasswordResetTokenByHash :one
SELECT id, user_id, expires_at, used_at, created_at
FROM password_reset_tokens
WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now();

-- name: MarkPasswordResetTokenUsed :exec
UPDATE password_reset_tokens SET used_at = now() WHERE id = $1;

-- name: CountRecentPasswordResetTokens :one
SELECT COUNT(*) FROM password_reset_tokens
WHERE user_id = $1 AND created_at > $2;

-- name: ConsumePasswordResetToken :one
-- Atomically marks a token as used and returns it, preventing concurrent use.
UPDATE password_reset_tokens
SET used_at = now()
WHERE id = (
    SELECT prt.id FROM password_reset_tokens prt
    WHERE prt.token_hash = @token_hash AND prt.used_at IS NULL AND prt.expires_at > now()
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, user_id, expires_at, used_at, created_at;

-- name: DeleteExpiredPasswordResetTokens :exec
DELETE FROM password_reset_tokens WHERE expires_at < now();
