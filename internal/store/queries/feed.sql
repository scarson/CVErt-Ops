-- name: UpsertFeedSyncState :exec
INSERT INTO feed_sync_state (
    feed_name, cursor_json, last_success_at, last_attempt_at,
    consecutive_failures, last_error, backoff_until
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (feed_name) DO UPDATE
    SET cursor_json          = EXCLUDED.cursor_json,
        last_success_at      = EXCLUDED.last_success_at,
        last_attempt_at      = EXCLUDED.last_attempt_at,
        consecutive_failures = EXCLUDED.consecutive_failures,
        last_error           = EXCLUDED.last_error,
        backoff_until        = EXCLUDED.backoff_until;

-- name: GetFeedSyncState :one
SELECT * FROM feed_sync_state WHERE feed_name = $1;

-- name: InsertFeedFetchLog :one
INSERT INTO feed_fetch_log (
    feed_name, started_at, ended_at, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id;

-- name: ListFeedSyncStates :many
SELECT * FROM feed_sync_state ORDER BY feed_name;

-- name: ListRecentFeedFetchLogs :many
SELECT * FROM feed_fetch_log
WHERE feed_name = $1
ORDER BY started_at DESC
LIMIT $2;

-- name: PauseFeed :exec
UPDATE feed_sync_state SET paused_at = now() WHERE feed_name = $1 AND paused_at IS NULL;

-- name: ResumeFeed :exec
UPDATE feed_sync_state SET paused_at = NULL WHERE feed_name = $1 AND paused_at IS NOT NULL;

-- name: ListFeedFetchLogs :many
-- Keyset-paginated feed fetch logs for a single feed.
SELECT * FROM feed_fetch_log
WHERE feed_name = $1
  AND (
    sqlc.narg('after_started_at')::timestamptz IS NULL
    OR (started_at, id) < (sqlc.narg('after_started_at')::timestamptz, sqlc.narg('after_id')::uuid)
  )
ORDER BY started_at DESC, id DESC
LIMIT $2;
