-- migrate:no-transaction

-- Fails while more than one pending digest delivery exists for a report and
-- channel. Let those deliveries complete before rolling back. A failed build
-- leaves an INVALID index behind, which IF NOT EXISTS then skips, so drop it
-- before retrying.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS uq_deliveries_pending_digest
    ON notification_deliveries (report_id, channel_id)
    WHERE status = 'pending' AND kind = 'digest';
