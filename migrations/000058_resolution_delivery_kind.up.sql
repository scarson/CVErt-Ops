-- migrate:no-transaction

-- A resolution delivery tells a rule's channels that CVEs stopped matching it.
-- It has its own kind so it never shares a batch with alerts: OrphanedAlertEvents
-- treats an alert delivery on a rule as proof the alert was sent, and a resolution
-- is not that proof.
-- Each constraint is replaced as NOT VALID in one statement and validated afterwards,
-- so the table is not locked for the scan and no window exists without a constraint.
ALTER TABLE notification_deliveries
    DROP CONSTRAINT IF EXISTS notification_deliveries_kind_check,
    ADD CONSTRAINT notification_deliveries_kind_check
        CHECK (kind IN ('alert', 'digest', 'resolution')) NOT VALID,
    DROP CONSTRAINT IF EXISTS delivery_kind_fk_check,
    ADD CONSTRAINT delivery_kind_fk_check CHECK (
        (kind IN ('alert', 'resolution') AND rule_id IS NOT NULL AND report_id IS NULL) OR
        (kind = 'digest' AND rule_id IS NULL AND report_id IS NOT NULL)
    ) NOT VALID;

ALTER TABLE notification_deliveries VALIDATE CONSTRAINT notification_deliveries_kind_check;
ALTER TABLE notification_deliveries VALIDATE CONSTRAINT delivery_kind_fk_check;

-- At most one resolution delivery per rule and channel collects CVEs during its
-- debounce window, as uq_deliveries_open_alert_batch does for alerts.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_open_resolution_batch
    ON notification_deliveries (rule_id, channel_id)
    WHERE status = 'pending' AND kind = 'resolution' AND batch_open;
