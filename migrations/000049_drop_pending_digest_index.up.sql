-- migrate:no-transaction

-- Each digest run inserts its own delivery row per channel. A unique index on
-- pending digest rows per (report_id, channel_id) dropped the next digest while
-- the previous one was still pending (waiting out a retry backoff), and made the
-- retry of a failed in-flight digest violate the index when the next digest was
-- already pending. See implementation-pitfalls.md NOTIFY-22.
DROP INDEX CONCURRENTLY IF EXISTS uq_deliveries_pending_digest;
