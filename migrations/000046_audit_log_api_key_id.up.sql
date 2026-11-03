-- Record which API key performed an audited action. actor_id stays the key's
-- creating user, and api_key_id is NULL for session and system actions.
-- NOT a FK, like actor_id: audit records must survive key deletion.
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS api_key_id UUID;
