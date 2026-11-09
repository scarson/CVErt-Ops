-- ABOUTME: sqlc queries for the notification_deliveries delivery job queue.
-- ABOUTME: Claim uses FOR UPDATE SKIP LOCKED and closes the alert batch; debounce uses ON CONFLICT partial index.

-- name: ClaimPendingDeliveries :many
SELECT id, org_id, rule_id, channel_id, kind, report_id, attempt_count, payload
FROM notification_deliveries
WHERE status = 'pending' AND send_after <= now()
ORDER BY send_after
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: MarkDeliveriesProcessing :exec
UPDATE notification_deliveries
SET status = 'processing', batch_open = false, last_attempted_at = now(), updated_at = now()
WHERE id = ANY($1::uuid[]);

-- name: CompleteDelivery :exec
UPDATE notification_deliveries
SET status = 'succeeded', delivered_at = now(), updated_at = now()
WHERE id = $1;

-- name: RetryDelivery :exec
-- Sets status back to pending with incremented attempt_count and backoff send_after.
-- The row stays a closed batch: newly matched CVEs go to the open batch instead.
UPDATE notification_deliveries
SET status        = 'pending',
    batch_open    = false,
    attempt_count = attempt_count + 1,
    send_after    = now() + ($2 * interval '1 second'),
    last_error    = $3,
    last_error_for_org = $4,
    updated_at    = now()
WHERE id = $1;

-- name: ExhaustDelivery :exec
-- Max attempts reached — move to permanent failure.
UPDATE notification_deliveries
SET status        = 'failed',
    attempt_count = attempt_count + 1,
    last_error    = $2,
    last_error_for_org = $3,
    updated_at    = now()
WHERE id = $1;

-- name: ResetStuckDeliveries :exec
-- Recovery: reset processing rows that haven't been updated in $1 seconds.
UPDATE notification_deliveries
SET status = 'pending', batch_open = false, send_after = now(), updated_at = now()
WHERE status = 'processing'
  AND updated_at < now() - ($1 * interval '1 second');

-- name: OrphanedAlertEvents :many
-- Recovery scan: alert_events with no corresponding delivery rows.
SELECT ae.org_id, ae.rule_id, ae.cve_id
FROM alert_events ae
WHERE ae.suppress_delivery = false
  AND ae.last_match_state  = true
  AND ae.last_fired_at < now() - interval '5 minutes'
  AND NOT EXISTS (
      SELECT 1
      FROM notification_deliveries nd
      WHERE nd.rule_id  = ae.rule_id
        AND nd.org_id   = ae.org_id
        AND nd.status   IN ('pending', 'processing', 'succeeded')
        AND nd.created_at >= ae.last_fired_at - interval '1 minute'
  )
LIMIT $1;

-- name: ListDeliveries :many
SELECT id, org_id, rule_id, channel_id, kind, report_id, status, attempt_count,
       send_after, last_attempted_at, delivered_at, last_error_for_org, created_at, updated_at
FROM notification_deliveries
WHERE org_id = $1
  AND ($2 = '00000000-0000-0000-0000-000000000000'::uuid OR rule_id    = $2)
  AND ($3 = '00000000-0000-0000-0000-000000000000'::uuid OR channel_id = $3)
  AND ($4 = ''                                           OR status      = $4)
  AND (created_at < $5 OR (created_at = $5 AND id < $6))
ORDER BY created_at DESC, id DESC
LIMIT $7;

-- name: GetDelivery :one
SELECT id, org_id, rule_id, channel_id, kind, report_id, status, attempt_count, payload,
       send_after, last_attempted_at, delivered_at, last_error_for_org, created_at, updated_at
FROM notification_deliveries
WHERE id = $1 AND org_id = $2
LIMIT 1;

-- name: InsertDigestDelivery :exec
-- Digest runner: insert a digest delivery for a report+channel.
-- Each digest run gets its own row, even while an earlier digest for the same
-- report and channel is still pending.
INSERT INTO notification_deliveries (org_id, report_id, channel_id, kind, payload, send_after)
VALUES ($1, $2, $3, 'digest', $4, now());

-- name: ReplayDelivery :exec
UPDATE notification_deliveries
SET status        = 'pending',
    batch_open    = false,
    attempt_count = 0,
    send_after    = now(),
    last_error    = NULL,
    last_error_for_org = NULL,
    updated_at    = now()
WHERE id = $1 AND org_id = $2
  AND status IN ('failed', 'cancelled');
