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

-- name: CreateMFARecoveryCode :exec
INSERT INTO mfa_recovery_codes (user_id, code_hash)
VALUES ($1, $2);

-- name: GetUnusedRecoveryCodeByHash :one
SELECT * FROM mfa_recovery_codes
WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL;

-- name: GetUnusedRecoveryCodeByHashForUpdate :one
SELECT * FROM mfa_recovery_codes
WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
FOR UPDATE SKIP LOCKED;

-- name: MarkRecoveryCodeUsed :exec
UPDATE mfa_recovery_codes SET used_at = now() WHERE id = $1;

-- name: CountUnusedRecoveryCodes :one
SELECT COUNT(*) FROM mfa_recovery_codes
WHERE user_id = $1 AND used_at IS NULL;

-- name: DeleteAllRecoveryCodes :execrows
DELETE FROM mfa_recovery_codes WHERE user_id = $1;

-- name: CreateMFAChallenge :one
INSERT INTO mfa_challenges (user_id, challenge_type, token_hash, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetActiveEmailOTPChallenge :one
SELECT * FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp' AND expires_at > now()
LIMIT 1;

-- name: GetActiveEmailOTPChallengeForUpdate :one
SELECT * FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp' AND expires_at > now()
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: IncrementChallengeAttempts :one
UPDATE mfa_challenges SET attempts = attempts + 1
WHERE id = $1
RETURNING attempts;

-- name: DeleteEmailOTPChallenges :execrows
DELETE FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp';

-- name: DeleteAllUserChallenges :execrows
DELETE FROM mfa_challenges WHERE user_id = $1;

-- name: DeleteRememberDeviceTokens :execrows
DELETE FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'remember_device';

-- name: GetRememberDeviceToken :one
SELECT * FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'remember_device'
  AND token_hash = $2 AND expires_at > now()
LIMIT 1;

-- name: CountRecentEmailOTPChallenges :one
SELECT COUNT(*) FROM mfa_challenges
WHERE user_id = $1 AND challenge_type = 'email_otp'
  AND created_at > $2;

-- name: DeleteExpiredChallenges :execrows
DELETE FROM mfa_challenges WHERE expires_at < now();

-- name: DeleteChallenge :exec
DELETE FROM mfa_challenges WHERE id = $1;

-- name: IsOrgOwner :one
-- Does this user have the 'owner' role in any org?
SELECT EXISTS(
    SELECT 1 FROM org_members WHERE user_id = $1 AND role = 'owner'
) AS is_owner;

-- name: CreateMFARequirement :exec
INSERT INTO mfa_requirements (org_id, user_id, required_by)
VALUES ($1, $2, $3)
ON CONFLICT (org_id, user_id) DO NOTHING;

-- name: DeleteMFARequirement :execrows
DELETE FROM mfa_requirements WHERE org_id = $1 AND user_id = $2;

-- name: GetMFARequirementsByOrg :many
SELECT * FROM mfa_requirements WHERE org_id = $1 ORDER BY created_at;

-- name: UserHasMFARequirement :one
-- Cross-org check: does this user have an MFA requirement in ANY org?
-- Used at login time under withBypassTx.
SELECT EXISTS(
    SELECT 1 FROM mfa_requirements WHERE user_id = $1
) AS required;

-- name: UserInMFARequiredOrg :one
-- Does this user belong to any org with mfa_required_all=true?
-- Used at login time under withBypassTx.
SELECT EXISTS(
    SELECT 1 FROM org_members om
    JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = $1 AND o.mfa_required_all = true
) AS required;
