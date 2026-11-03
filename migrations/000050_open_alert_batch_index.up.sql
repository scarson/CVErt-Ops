-- migrate:no-transaction

-- batch_open marks the one alert delivery per (rule_id, channel_id) that still
-- collects newly matched CVEs during its debounce window. UpsertDelivery inserts
-- it as open, and claiming it for a send closes it for good. A delivery that
-- returns to pending after a send attempt (retry, stuck-row reset, replay, admin
-- retry) is a closed batch with its own attempt count and backoff, and any
-- number of closed batches may be pending for the same rule and channel.
-- A unique index on every pending alert delivery made those returns violate the
-- index whenever a newer batch was pending. See implementation-pitfalls.md NOTIFY-25.
ALTER TABLE notification_deliveries
    ADD COLUMN IF NOT EXISTS batch_open BOOLEAN NOT NULL DEFAULT false;

-- Pending alert deliveries that were never claimed are the open batches.
-- uq_deliveries_pending_alert allows at most one of them per rule and channel.
UPDATE notification_deliveries
SET batch_open = true
WHERE status = 'pending' AND kind = 'alert' AND last_attempted_at IS NULL;

-- Build the open-batch index before dropping the pending index, so the debounce
-- is enforced throughout.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_open_alert_batch
    ON notification_deliveries (rule_id, channel_id)
    WHERE status = 'pending' AND kind = 'alert' AND batch_open;

DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_alert;
