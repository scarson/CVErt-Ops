ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT 'free';
ALTER TABLE organizations ADD CONSTRAINT organizations_tier_check CHECK (tier IN ('free', 'pro', 'enterprise'));
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier_overrides JSONB NOT NULL DEFAULT '{}';
