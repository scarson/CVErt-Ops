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
    feed_name, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary, ended_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
RETURNING id;
