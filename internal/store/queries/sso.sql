-- ABOUTME: sqlc queries for SSO connection and email domain management.
-- ABOUTME: SSO connections are org-scoped (UNIQUE on org_id), email domains are globally unique.

-- name: CreateSSOConnection :one
INSERT INTO sso_connections (org_id, display_name, issuer_url, client_id, client_secret_enc, scopes, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *;

-- name: GetSSOConnection :one
SELECT * FROM sso_connections WHERE org_id = $1;

-- name: UpdateSSOConnection :exec
UPDATE sso_connections SET display_name = $2, issuer_url = $3, client_id = $4,
    client_secret_enc = $5, scopes = $6, enabled = $7, updated_at = now()
WHERE org_id = $1;

-- name: DeleteSSOConnection :exec
DELETE FROM sso_connections WHERE org_id = $1;

-- name: UpsertSSOEmailDomain :exec
INSERT INTO sso_email_domains (domain, sso_connection_id, org_id)
VALUES ($1, $2, $3);

-- name: DeleteSSOEmailDomains :exec
DELETE FROM sso_email_domains WHERE sso_connection_id = $1;

-- name: ListSSOEmailDomains :many
SELECT domain FROM sso_email_domains WHERE sso_connection_id = $1 ORDER BY domain;

-- name: LookupSSOByDomain :one
SELECT sc.id, sc.org_id, sc.display_name, sc.issuer_url, sc.client_id, sc.scopes, sc.enabled
FROM sso_email_domains sed
JOIN sso_connections sc ON sed.sso_connection_id = sc.id
WHERE sed.domain = $1 AND sc.enabled = true;

-- name: GetSSOConnectionByID :one
SELECT * FROM sso_connections WHERE id = $1;
