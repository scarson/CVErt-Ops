-- migrate:no-transaction
-- Index operations use CONCURRENTLY.

-- ── notification_channels alterations ──────────────────────────────────────────

-- Email channels don't need signing secrets.
ALTER TABLE notification_channels ALTER COLUMN signing_secret DROP NOT NULL;

-- Extend channel type to include 'email'.
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook', 'email'));

-- Email channels store {"recipients": [...]} — webhook URL check is type-specific.
-- The existing nc_webhook_url CHECK already handles this correctly:
-- "type != 'webhook' OR jsonb_exists(config, 'url')" evaluates TRUE for email channels.

-- ── notification_deliveries alterations ────────────────────────────────────────

-- Add delivery kind discriminator.
ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'alert'
    CHECK (kind IN ('alert', 'digest'));

-- Make rule_id nullable: digest deliveries have report_id instead.
ALTER TABLE notification_deliveries ALTER COLUMN rule_id DROP NOT NULL;

-- Add report_id FK for digest deliveries.
ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS report_id UUID NULL REFERENCES scheduled_reports(id) ON DELETE CASCADE;

-- Exactly one of rule_id or report_id must be set, matching kind.
ALTER TABLE notification_deliveries
    ADD CONSTRAINT delivery_kind_fk_check CHECK (
        (kind = 'alert'  AND rule_id IS NOT NULL AND report_id IS NULL) OR
        (kind = 'digest' AND rule_id IS NULL     AND report_id IS NOT NULL)
    );

-- Recreate debounce indexes: create new ones first (no unprotected window).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_alert
    ON notification_deliveries (rule_id, channel_id)
    WHERE status = 'pending' AND kind = 'alert';

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_digest
    ON notification_deliveries (report_id, channel_id)
    WHERE status = 'pending' AND kind = 'digest';

-- Drop old debounce index (superseded by kind-aware ones above).
DROP INDEX CONCURRENTLY IF EXISTS uq_notification_deliveries_pending;

-- Index for delivery history queries filtered by report.
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_deliveries_report_id_idx
    ON notification_deliveries (report_id);
