-- The CVE versions the last digest sent whose date_modified_canonical lies
-- within the re-scan window behind last_run_at, as a JSON array of
-- {"cve_id", "date_modified_canonical"} objects. Each digest scan starts that
-- window before last_run_at, so CVEs committed after the previous scan are not
-- lost. These entries keep the versions already sent out of the next digest.
-- Bounded by the 500-row digest limit plus entries still inside the window.
ALTER TABLE scheduled_reports ADD COLUMN IF NOT EXISTS rescan_sent_cves JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE scheduled_reports ADD CONSTRAINT scheduled_reports_rescan_sent_cves_array
    CHECK (jsonb_typeof(rescan_sent_cves) = 'array');
