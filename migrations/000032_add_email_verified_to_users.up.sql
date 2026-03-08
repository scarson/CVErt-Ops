-- migrate:no-transaction
-- ABOUTME: Adds email_verified boolean to users table.
-- ABOUTME: Default false — existing users are unverified until they verify.

ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
