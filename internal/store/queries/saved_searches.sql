-- ABOUTME: sqlc queries for saved search CRUD with soft-delete.
-- ABOUTME: Supports private/shared visibility filtering and orphaned-search cleanup.

-- name: CreateSavedSearch :one
INSERT INTO saved_searches (org_id, user_id, name, query_json, nl_query, is_shared)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetSavedSearch :one
SELECT * FROM saved_searches
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: ListSavedSearches :many
SELECT * FROM saved_searches
WHERE org_id = $1 AND deleted_at IS NULL
  AND (
    CASE
      WHEN @visibility::text = 'private' THEN is_shared = false AND user_id = @user_id::uuid
      WHEN @visibility::text = 'shared' THEN is_shared = true
      ELSE (is_shared = true OR user_id = @user_id::uuid)
    END
  )
ORDER BY updated_at DESC;

-- name: UpdateSavedSearch :one
UPDATE saved_searches
SET name       = $3,
    query_json = $4,
    nl_query   = $5,
    is_shared  = $6,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteSavedSearch :exec
UPDATE saved_searches SET deleted_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: CleanupOrphanedPrivateSavedSearches :exec
DELETE FROM saved_searches
WHERE user_id = $1 AND is_shared = false;
