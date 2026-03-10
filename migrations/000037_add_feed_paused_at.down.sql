-- Reverse: drop feed paused_at column.
ALTER TABLE feed_sync_state DROP COLUMN IF EXISTS paused_at;
