-- ABOUTME: Creates the cvert_ops_app database role with NOBYPASSRLS.
-- ABOUTME: Run once at initial DB creation via docker-entrypoint-initdb.d.

-- Create the restricted application role if it does not already exist.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cvert_ops_app') THEN
        CREATE ROLE cvert_ops_app
            LOGIN
            NOBYPASSRLS
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE;
    END IF;
END
$$;

-- Set the password. In production, use a secrets manager instead.
-- ALTER ROLE cvert_ops_app WITH PASSWORD 'changeme';

-- Grant the app role access to the database.
GRANT CONNECT ON DATABASE cvert_ops TO cvert_ops_app;

-- Grant schema usage. Tables will be granted per-migration.
GRANT USAGE ON SCHEMA public TO cvert_ops_app;
