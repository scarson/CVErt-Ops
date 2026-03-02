-- migrate:no-transaction

DROP POLICY IF EXISTS org_isolation ON sso_email_domains;
ALTER TABLE sso_email_domains DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS sso_email_domains;

DROP POLICY IF EXISTS org_isolation ON sso_connections;
ALTER TABLE sso_connections DISABLE ROW LEVEL SECURITY;
DROP TABLE IF EXISTS sso_connections;
