-- The delivery failure text that org members may read. last_error keeps the
-- full text for site admins, which can include addresses a webhook host name
-- resolved to. last_error_for_org replaces failures from before the receiver
-- answered with a fixed message, so org endpoints cannot be used to map the
-- instance's internal DNS.
-- The CHECK keeps the two columns set and cleared together.
ALTER TABLE notification_deliveries ADD COLUMN IF NOT EXISTS last_error_for_org TEXT;

ALTER TABLE notification_deliveries ADD CONSTRAINT notification_deliveries_last_error_pair
    CHECK ((last_error IS NULL) = (last_error_for_org IS NULL));
