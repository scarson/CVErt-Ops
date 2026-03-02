-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON audit_log;
ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS audit_log;
