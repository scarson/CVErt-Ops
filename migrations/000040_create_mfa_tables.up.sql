-- migrate:no-transaction
-- ABOUTME: MFA tables for TOTP, email OTP, recovery codes, challenges, and per-member requirements.
-- ABOUTME: See dev/plans/2026-03-16-mfa-totp-email-otp-design.md for design rationale.

-- mfa_credentials: one row per enrolled MFA method per user (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method          TEXT NOT NULL,
    secret_enc      BYTEA,
    last_used_step  BIGINT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE(user_id, method),
    CONSTRAINT mfa_cred_method      CHECK (method IN ('totp', 'email_otp')),
    CONSTRAINT mfa_cred_totp_secret CHECK (method != 'totp' OR secret_enc IS NOT NULL),
    CONSTRAINT mfa_cred_email_null  CHECK (method != 'email_otp' OR (secret_enc IS NULL AND last_used_step IS NULL))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_credentials TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_credentials_user_id ON mfa_credentials(user_id);

-- mfa_recovery_codes: per-user one-time recovery codes (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, code_hash)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_recovery_codes TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);

-- mfa_challenges: active email OTP codes and remember-device tokens (global, no RLS)
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_type  TEXT NOT NULL,
    token_hash      TEXT NOT NULL,
    attempts        INT NOT NULL DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT mfa_challenge_type CHECK (challenge_type IN ('email_otp', 'remember_device'))
);

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_challenges TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);

-- mfa_requirements: per-member MFA mandates set by org owners/admins (org-scoped, RLS)
CREATE TABLE IF NOT EXISTS mfa_requirements (
    org_id          UUID NOT NULL,
    user_id         UUID NOT NULL,
    required_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id),
    FOREIGN KEY (org_id, user_id) REFERENCES org_members(org_id, user_id) ON DELETE CASCADE
);

ALTER TABLE mfa_requirements ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_requirements FORCE ROW LEVEL SECURITY;
CREATE POLICY mfa_requirements_policy ON mfa_requirements
    USING (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    )
    WITH CHECK (
        current_setting('app.bypass_rls', TRUE) = 'on'
        OR org_id = current_setting('app.org_id', TRUE)::uuid
    );

GRANT SELECT, INSERT, DELETE ON mfa_requirements TO cvert_ops_app;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_mfa_requirements_user_id ON mfa_requirements(user_id);

-- force_password_reset already exists (added in migration 000036).

-- Add org-level MFA settings
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_required_all BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_remember_device_allowed BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS mfa_remember_device_days INT NOT NULL DEFAULT 30;

-- Add CHECK constraint for remember device days range.
-- DROP + ADD for idempotency (golang-migrate doesn't support DO $$ blocks in no-transaction mode).
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS mfa_remember_days_range;
ALTER TABLE organizations ADD CONSTRAINT mfa_remember_days_range
    CHECK (mfa_remember_device_days BETWEEN 7 AND 90);
