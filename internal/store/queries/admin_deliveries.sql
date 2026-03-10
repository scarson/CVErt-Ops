-- ABOUTME: sqlc queries for site admin delivery management (cross-org).
-- ABOUTME: All queries run via withBypassTx (admin operates across all orgs).

-- name: AdminGetDeliveryByID :one
SELECT id, org_id, rule_id, channel_id, kind, report_id, status, attempt_count,
       send_after, last_attempted_at, delivered_at, last_error, created_at, updated_at
FROM notification_deliveries
WHERE id = $1;

-- name: AdminRetryDelivery :execresult
-- Retry a single delivery: reset to pending only if failed or dead_letter.
UPDATE notification_deliveries
SET status        = 'pending',
    attempt_count = 0,
    send_after    = now(),
    last_error    = NULL,
    updated_at    = now()
WHERE id = $1 AND status IN ('failed');

-- name: AdminBulkRetryFailed :execresult
-- Bulk retry: reset up to $1 failed deliveries back to pending.
UPDATE notification_deliveries
SET status        = 'pending',
    attempt_count = 0,
    send_after    = now(),
    last_error    = NULL,
    updated_at    = now()
WHERE id IN (
    SELECT id FROM notification_deliveries
    WHERE status = 'failed'
    ORDER BY created_at DESC
    LIMIT $1
);
