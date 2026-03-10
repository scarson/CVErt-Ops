-- ABOUTME: sqlc queries for site admin system management (cross-org).
-- ABOUTME: Cross-org audit log listing. Runs via withBypassTx.

-- name: AdminListAuditEntries :many
-- Cross-org audit log listing with optional filters and keyset pagination.
SELECT * FROM audit_log
WHERE (@entity_type::text = '' OR entity_type = @entity_type::text)
  AND (@action::text = '' OR action = @action::text)
  AND (sqlc.narg('org_id')::uuid IS NULL OR org_id = sqlc.narg('org_id')::uuid)
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_id = sqlc.narg('actor_id')::uuid)
  AND (
      sqlc.narg('cursor_created_at')::timestamptz IS NULL
      OR (created_at, id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY created_at DESC, id DESC
LIMIT @page_size::int;
