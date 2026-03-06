ALTER TABLE organizations DROP COLUMN IF EXISTS tier_overrides;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_tier_check;
ALTER TABLE organizations DROP COLUMN IF EXISTS tier;
