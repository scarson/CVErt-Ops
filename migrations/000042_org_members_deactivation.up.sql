-- migrate:no-transaction
-- ABOUTME: Adds deactivation and SCIM exemption to org_members.
-- ABOUTME: deactivated_at is a general feature (admin-settable), scim_exempt prevents SCIM from modifying state.

ALTER TABLE org_members ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS scim_exempt BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX CONCURRENTLY IF NOT EXISTS org_members_active_idx
    ON org_members (org_id) WHERE deactivated_at IS NULL;
