-- ABOUTME: sqlc queries for alert rule ↔ notification channel M:M bindings.
-- ABOUTME: Hard-delete join table; no soft-delete.

-- name: BindChannelToRule :exec
INSERT INTO alert_rule_channels (rule_id, channel_id, org_id)
VALUES ($1, $2, $3)
ON CONFLICT (rule_id, channel_id) DO NOTHING;

-- name: UnbindChannelFromRule :exec
DELETE FROM alert_rule_channels
WHERE rule_id = $1 AND channel_id = $2 AND org_id = $3;

-- name: ListChannelsForRule :many
SELECT nc.id, nc.org_id, nc.name, nc.type, nc.config, nc.created_at, nc.updated_at
FROM alert_rule_channels arc
JOIN notification_channels nc ON nc.id = arc.channel_id
WHERE arc.rule_id = $1 AND arc.org_id = $2
  AND nc.deleted_at IS NULL
ORDER BY arc.created_at;

-- name: ListActiveChannelsForFanout :many
-- Used by Dispatcher.Fanout: fetches channel config + secrets for delivery row creation.
SELECT nc.id, nc.type, nc.config, nc.signing_secret, nc.signing_secret_secondary
FROM alert_rule_channels arc
JOIN notification_channels nc ON nc.id = arc.channel_id
WHERE arc.rule_id = $1 AND arc.org_id = $2
  AND nc.deleted_at IS NULL;

-- name: ChannelRuleBindingExists :one
SELECT EXISTS(
    SELECT 1 FROM alert_rule_channels
    WHERE rule_id = $1 AND channel_id = $2 AND org_id = $3
) AS exists;
