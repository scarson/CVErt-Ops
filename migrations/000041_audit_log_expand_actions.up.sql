-- Expand audit_log action check constraint to include all actions used by handlers.
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_action_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_action_check
    CHECK (action IN ('create', 'update', 'delete', 'revoke', 'add', 'remove', 'bind', 'unbind', 'update_domains'));
