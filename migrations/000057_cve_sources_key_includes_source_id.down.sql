-- ABOUTME: Restores the one-row-per-source key on cve_sources.
-- ABOUTME: Keeps the row with the lowest source_id for each CVE and source.

DELETE FROM cve_sources a USING cve_sources b
WHERE a.cve_id = b.cve_id AND a.source_name = b.source_name AND a.source_id > b.source_id;

ALTER TABLE cve_sources DROP CONSTRAINT cve_sources_pkey,
    ADD CONSTRAINT cve_sources_pkey PRIMARY KEY (cve_id, source_name);

ALTER TABLE cve_sources ALTER COLUMN source_id DROP NOT NULL;
