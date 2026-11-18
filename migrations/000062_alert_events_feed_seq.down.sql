-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).

DROP INDEX CONCURRENTLY IF EXISTS alert_events_feed_seq_uq;

-- Dropping the column drops the sequence it owns.
ALTER TABLE alert_events DROP COLUMN IF EXISTS feed_seq;

DROP SEQUENCE IF EXISTS alert_event_feed_seq;
