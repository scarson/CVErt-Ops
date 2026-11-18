-- migrate:no-transaction

-- Fails while more than one pending alert delivery exists for a rule and
-- channel. Let those deliveries complete before rolling back. A failed build
-- leaves an INVALID index behind, which IF NOT EXISTS then skips, so drop it
-- before retrying.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_alert
    ON notification_deliveries (rule_id, channel_id)
    WHERE status = 'pending' AND kind = 'alert';

DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_open_alert_batch;

ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS batch_open;
