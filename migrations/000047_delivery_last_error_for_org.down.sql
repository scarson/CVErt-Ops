ALTER TABLE notification_deliveries DROP CONSTRAINT IF EXISTS notification_deliveries_last_error_pair;

ALTER TABLE notification_deliveries DROP COLUMN IF EXISTS last_error_for_org;
