-- ABOUTME: sqlc queries for scheduled_reports digest configuration CRUD.
-- ABOUTME: Runner ops (claim, advance) use bypass-RLS. API ops use org-scoped tx.

-- name: CreateScheduledReport :one
INSERT INTO scheduled_reports (
    org_id, name, scheduled_time, timezone, next_run_at,
    severity_threshold, watchlist_ids, send_on_empty, ai_summary, status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetScheduledReport :one
SELECT * FROM scheduled_reports
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: ListScheduledReports :many
SELECT * FROM scheduled_reports
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC;

-- name: UpdateScheduledReport :one
UPDATE scheduled_reports
SET name               = $3,
    scheduled_time     = $4,
    timezone           = $5,
    next_run_at        = $6,
    severity_threshold = $7,
    watchlist_ids      = $8,
    send_on_empty      = $9,
    ai_summary         = $10,
    status             = $11,
    updated_at         = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING *;

-- name: SoftDeleteScheduledReport :exec
UPDATE scheduled_reports
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: ClaimDueReport :one
-- Digest runner: claim the earliest due report that is not in skip_ids and not
-- held by another run. The row lock lasts until the caller's transaction ends.
SELECT * FROM scheduled_reports
WHERE status = 'active'
  AND next_run_at <= now()
  AND deleted_at IS NULL
  AND id <> ALL(@skip_ids::uuid[])
ORDER BY next_run_at
LIMIT 1
FOR UPDATE SKIP LOCKED;

-- name: AdvanceReport :exec
-- After a digest run: update last_run_at, next_run_at, and the sent CVE
-- versions the next run's re-scan window must leave out.
UPDATE scheduled_reports
SET last_run_at      = $2,
    next_run_at      = $3,
    rescan_sent_cves = $4,
    updated_at       = now()
WHERE id = $1;

-- name: GetAlertRuleName :one
-- Lightweight lookup for template rendering.
SELECT name FROM alert_rules WHERE id = $1 LIMIT 1;

-- name: GetScheduledReportName :one
-- Lightweight lookup for template rendering.
SELECT name FROM scheduled_reports WHERE id = $1 LIMIT 1;
