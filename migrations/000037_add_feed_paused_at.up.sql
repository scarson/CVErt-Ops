-- Feed pause/resume: admin can pause and resume individual feeds.
ALTER TABLE feed_sync_state ADD COLUMN IF NOT EXISTS paused_at timestamptz;
