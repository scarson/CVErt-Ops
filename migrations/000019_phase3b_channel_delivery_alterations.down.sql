-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS notification_deliveries_report_id_idx;

-- Restore original debounce index.
-- Safe: all existing rows with kind='alert' have non-null rule_id.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_notification_deliveries_pending
    ON notification_deliveries (rule_id, channel_id) WHERE status = 'pending';

DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_digest;
DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_alert;

ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS delivery_kind_fk_check;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS report_id;
ALTER TABLE notification_deliveries ALTER COLUMN rule_id SET NOT NULL;
ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS kind;

ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook'));
ALTER TABLE notification_channels ALTER COLUMN signing_secret SET NOT NULL;
