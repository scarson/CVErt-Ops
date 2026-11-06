#!/usr/bin/env bash
# ABOUTME: Creates the cvert_ops_app database role (NOBYPASSRLS) with the password from APP_DB_PASSWORD.
# ABOUTME: Run by the Postgres image on first initialization of an empty data volume.

set -e

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

# psql reads the values from the environment and quotes them itself, so any
# character is safe in the password and no value appears on a command line.
# The heredoc is quoted so the shell leaves the psql variables alone.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'SQL'
\getenv app_password APP_DB_PASSWORD
\getenv database_name POSTGRES_DB

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

ALTER ROLE cvert_ops_app WITH LOGIN PASSWORD :'app_password';

-- Grant the app role access to the database.
GRANT CONNECT ON DATABASE :"database_name" TO cvert_ops_app;

-- Grant schema usage. Tables will be granted per-migration.
GRANT USAGE ON SCHEMA public TO cvert_ops_app;

-- Default privileges ensure future tables/sequences created by the superuser
-- are automatically accessible to the app role. Migrations also include
-- explicit per-table GRANTs as a second safety layer.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cvert_ops_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO cvert_ops_app;
SQL
