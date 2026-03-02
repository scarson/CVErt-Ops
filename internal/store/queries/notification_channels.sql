-- ABOUTME: sqlc queries for notification channel CRUD.
-- ABOUTME: Secrets (signing_secret) are excluded from most queries; use GetChannelForDelivery.

-- name: CreateNotificationChannel :one
INSERT INTO notification_channels (org_id, name, type, config, signing_secret)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, org_id, name, type, config, deleted_at, created_at, updated_at;

-- name: GetNotificationChannel :one
SELECT id, org_id, name, type, config, deleted_at, created_at, updated_at
FROM notification_channels
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
LIMIT 1;

-- name: GetNotificationChannelForDelivery :one
-- Includes signing secrets — used by delivery worker only; never exposed via API.
SELECT id, org_id, type, config, signing_secret, signing_secret_secondary
FROM notification_channels
WHERE id = $1 AND deleted_at IS NULL
LIMIT 1;

-- name: ListNotificationChannels :many
SELECT id, org_id, name, type, config, deleted_at, created_at, updated_at
FROM notification_channels
WHERE org_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC, id DESC;

-- name: UpdateNotificationChannel :one
-- Full replacement of mutable fields. Handler reads existing record and applies
-- pointer-typed patch fields before calling this.
UPDATE notification_channels
SET name       = $3,
    config     = $4,
    updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING id, org_id, name, type, config, deleted_at, created_at, updated_at;

-- name: SoftDeleteNotificationChannel :exec
UPDATE notification_channels
SET deleted_at = now(), updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: RotateSigningSecret :one
-- Atomically moves primary → secondary, sets new primary.
UPDATE notification_channels
SET signing_secret_secondary = signing_secret,
    signing_secret           = $3,
    updated_at               = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL
RETURNING signing_secret;

-- name: ClearSecondarySecret :exec
UPDATE notification_channels
SET signing_secret_secondary = NULL, updated_at = now()
WHERE id = $1 AND org_id = $2 AND deleted_at IS NULL;

-- name: ChannelHasActiveBoundRules :one
-- Pre-flight check before soft-delete. Active = not draft/disabled/deleted.
SELECT EXISTS(
    SELECT 1
    FROM alert_rule_channels arc
    JOIN alert_rules ar ON ar.id = arc.rule_id
    WHERE arc.channel_id = $1
      AND ar.org_id = $2
      AND ar.status NOT IN ('draft', 'disabled', 'deleted')
      AND ar.deleted_at IS NULL
) AS has_active_rules;
