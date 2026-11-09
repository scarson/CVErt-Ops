-- migrate:no-transaction

DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_open_resolution_batch;

-- The restored constraints reject resolution rows, and a binary from before this
-- migration cannot deliver them.
DELETE FROM notification_deliveries WHERE kind = 'resolution';

ALTER TABLE notification_deliveries
    DROP CONSTRAINT IF EXISTS delivery_kind_fk_check,
    ADD CONSTRAINT delivery_kind_fk_check CHECK (
        (kind = 'alert'  AND rule_id IS NOT NULL AND report_id IS NULL) OR
        (kind = 'digest' AND rule_id IS NULL     AND report_id IS NOT NULL)
    ),
    DROP CONSTRAINT IF EXISTS notification_deliveries_kind_check,
    ADD CONSTRAINT notification_deliveries_kind_check
        CHECK (kind IN ('alert', 'digest'));
