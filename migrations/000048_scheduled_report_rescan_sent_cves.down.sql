ALTER TABLE scheduled_reports DROP CONSTRAINT IF EXISTS scheduled_reports_rescan_sent_cves_array;

ALTER TABLE scheduled_reports DROP COLUMN IF EXISTS rescan_sent_cves;
