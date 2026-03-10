-- Admin management columns for site admin org/user management endpoints.
-- No indexes needed — these columns are set by admin actions, not queried in hot paths.

-- Organization suspension (admin can suspend/unsuspend orgs).
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS suspended_at timestamptz;

-- User disable/enable (admin action, checked by auth middleware).
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at timestamptz;

-- Account lockout (brute-force protection, unlockable by admin).
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_count int NOT NULL DEFAULT 0;

-- Admin-forced password reset on next login.
ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_reset boolean NOT NULL DEFAULT false;
