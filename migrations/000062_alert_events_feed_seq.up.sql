-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.

-- feed_seq is an event's position in the ascending alert-event feed. A poller keeps
-- the last position it read and asks for larger ones, so positions must become
-- visible in position order: a row must never commit after a row with a larger
-- position in the same org. A plain sequence does not ensure that, since its value
-- is taken at insert and the row appears at commit (implementation-pitfalls.md API-12).
-- Every writer of feed_seq therefore takes the org's feed lock first,
--     SELECT pg_advisory_xact_lock(1178944836, hashtext(org_id::text))
-- and only then draws nextval('alert_event_feed_seq'). The lock is released after the
-- commit is visible, so the next writer in the org draws a larger value only after
-- the previous row is visible or rolled back. The column has no default, so an
-- insert that does not draw a position fails instead of taking one without the lock.
-- The sequence must keep CACHE 1 (the default): cached values would be handed out
-- in a different order from the lock.
CREATE SEQUENCE IF NOT EXISTS alert_event_feed_seq AS bigint CACHE 1;

GRANT USAGE ON SEQUENCE alert_event_feed_seq TO cvert_ops_app;

ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS feed_seq bigint;

ALTER SEQUENCE alert_event_feed_seq OWNED BY alert_events.feed_seq;

-- Existing events become history before every new position: -N for the oldest up
-- to -1 for the newest, by first fire. New positions start at 1. Running the down
-- migration and then this one again restarts the sequence at 1, so a poller holding
-- a cursor from before must start over. That only matters on a development database.
UPDATE alert_events ae
SET feed_seq = history.position_from_newest
FROM (
    SELECT id, -row_number() OVER (ORDER BY first_fired_at DESC, id DESC) AS position_from_newest
    FROM alert_events
    WHERE feed_seq IS NULL
) history
WHERE ae.id = history.id;

ALTER TABLE alert_events ALTER COLUMN feed_seq SET NOT NULL;

COMMENT ON COLUMN alert_events.feed_seq IS
    'Position in the alert-event feed. Draw it with nextval(''alert_event_feed_seq'') only while holding pg_advisory_xact_lock(1178944836, hashtext(org_id::text)).';

-- GET /alert-events?order=asc: WHERE org_id = $1 AND feed_seq > $2 ORDER BY feed_seq.
-- Unique, since the cursor is the position alone.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS alert_events_feed_seq_uq
    ON alert_events (org_id, feed_seq);
