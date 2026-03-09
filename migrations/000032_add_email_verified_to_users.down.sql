-- migrate:no-transaction
ALTER TABLE users DROP COLUMN IF EXISTS email_verified;
