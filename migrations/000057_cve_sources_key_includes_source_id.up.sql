-- ABOUTME: Keys cve_sources on the native advisory ID, so several advisories from one feed can describe one CVE.
-- ABOUTME: Every feed sets source_id, and ingest stores the CVE ID when a custom feed sends none.

ALTER TABLE cve_sources ALTER COLUMN source_id SET NOT NULL;

ALTER TABLE cve_sources DROP CONSTRAINT cve_sources_pkey,
    ADD CONSTRAINT cve_sources_pkey PRIMARY KEY (cve_id, source_name, source_id);
