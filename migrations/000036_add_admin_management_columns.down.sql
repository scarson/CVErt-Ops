-- Reverse: drop admin management columns.
ALTER TABLE users DROP COLUMN IF EXISTS force_password_reset;
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_count;
ALTER TABLE users DROP COLUMN IF EXISTS locked_at;
ALTER TABLE users DROP COLUMN IF EXISTS disabled_at;
ALTER TABLE organizations DROP COLUMN IF EXISTS suspended_at;
