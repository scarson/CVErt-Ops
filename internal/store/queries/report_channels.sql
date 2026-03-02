-- ABOUTME: sqlc queries for scheduled report ↔ notification channel M:M bindings.
-- ABOUTME: Hard-delete join table; mirrors alert_rule_channels pattern.

-- name: BindChannelToReport :exec
INSERT INTO report_channels (report_id, channel_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (report_id, channel_id) DO NOTHING;

-- name: UnbindChannelFromReport :exec
DELETE FROM report_channels
WHERE report_id = $1 AND channel_id = $2 AND org_id = $3;

-- name: ListChannelsForReport :many
SELECT nc.id, nc.org_id, nc.name, nc.type, nc.config, nc.created_at, nc.updated_at
FROM report_channels rc
JOIN notification_channels nc ON nc.id = rc.channel_id
WHERE rc.report_id = $1 AND rc.org_id = $2
  AND nc.deleted_at IS NULL
ORDER BY rc.created_at;

-- name: ListActiveChannelsForDigest :many
-- Used by digest runner: fetches channel config + secrets for delivery creation.
SELECT nc.id, nc.type, nc.config, nc.signing_secret, nc.signing_secret_secondary
FROM report_channels rc
JOIN notification_channels nc ON nc.id = rc.channel_id
WHERE rc.report_id = $1 AND rc.org_id = $2
  AND nc.deleted_at IS NULL;

-- name: ReportChannelBindingExists :one
SELECT EXISTS(
    SELECT 1 FROM report_channels
    WHERE report_id = $1 AND channel_id = $2 AND org_id = $3
) AS binding_exists;

-- name: ChannelHasActiveBoundReports :one
-- Pre-flight check before channel soft-delete.
SELECT EXISTS(
    SELECT 1
    FROM report_channels rc
    JOIN scheduled_reports sr ON sr.id = rc.report_id
    WHERE rc.channel_id = $1
      AND sr.org_id = $2
      AND sr.status = 'active'
      AND sr.deleted_at IS NULL
) AS has_active_reports;
