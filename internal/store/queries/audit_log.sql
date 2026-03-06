-- ABOUTME: sqlc queries for the append-only audit log.
-- ABOUTME: Insert for write path, paginated list for the audit API endpoint.

-- name: InsertAuditEntry :exec
INSERT INTO audit_log (org_id, actor_id, actor_email, action, entity_type, entity_id, entity_name, success, old_state, new_state, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: ListAuditEntries :many
SELECT * FROM audit_log
WHERE org_id = @org_id::uuid
  AND (@entity_type::text = '' OR entity_type = @entity_type::text)
  AND (@action::text = '' OR action = @action::text)
  AND (sqlc.narg('actor_id')::uuid IS NULL OR actor_id = sqlc.narg('actor_id')::uuid)
  AND created_at >= @after::timestamptz
  AND created_at <= @before::timestamptz
  AND (
      sqlc.narg('cursor_created_at')::timestamptz IS NULL
      OR (created_at, id) < (sqlc.narg('cursor_created_at')::timestamptz, sqlc.narg('cursor_id')::uuid)
  )
ORDER BY created_at DESC, id DESC
LIMIT @page_size::int;
