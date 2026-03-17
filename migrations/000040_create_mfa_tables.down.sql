-- migrate:no-transaction
-- ABOUTME: Rollback MFA tables and org-level MFA columns.
-- ABOUTME: Drops in reverse dependency order.

-- Drop org-level MFA columns
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS mfa_remember_days_range;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_remember_device_days;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_remember_device_allowed;
ALTER TABLE organizations DROP COLUMN IF EXISTS mfa_required_all;

-- Note: force_password_reset on users is NOT dropped here because it was
-- added in migration 000036 and may be used by other features.

-- Drop tables in reverse dependency order
DROP TABLE IF EXISTS mfa_requirements;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS mfa_recovery_codes;
DROP TABLE IF EXISTS mfa_credentials;
