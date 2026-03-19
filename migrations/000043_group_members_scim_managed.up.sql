-- ABOUTME: Adds scim_managed flag to group_members for SCIM notification sync tracking.
-- ABOUTME: SCIM removal only deletes scim_managed=true rows. Manual memberships preserved.

ALTER TABLE group_members ADD COLUMN IF NOT EXISTS scim_managed BOOLEAN NOT NULL DEFAULT false;
