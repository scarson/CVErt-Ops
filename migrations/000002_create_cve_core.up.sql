-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall §11.2).

-- pg_trgm enables trigram similarity search on CVE description text.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ============================================================
-- cves: global CVE corpus canonical row (one row per CVE ID).
-- FTS document lives in cve_search_index (1:1) to avoid GIN
-- rewrites on every score/timestamp update (§8.1, pitfall §11.1).
-- ============================================================
CREATE TABLE IF NOT EXISTS cves (
    cve_id                   text        PRIMARY KEY,
    status                   text,                              -- "Analyzed", "Rejected", "Modified", etc.
    date_published           timestamptz,
    date_modified_source_max timestamptz,                       -- max(source_date_modified) across cve_sources
    date_modified_canonical  timestamptz NOT NULL DEFAULT now(), -- updated only when material_hash changes
    date_first_seen          timestamptz NOT NULL DEFAULT now(),
    description_primary      text,
    severity                 text,                              -- "CRITICAL","HIGH","MEDIUM","LOW","NONE"
    cvss_v3_score            float8,
    cvss_v3_vector           text,
    cvss_v3_source           text,
    cvss_v4_score            float8,
    cvss_v4_vector           text,
    cvss_v4_source           text,
    cvss_score_diverges      bool        NOT NULL DEFAULT false,
    cwe_ids                  text[]      NOT NULL DEFAULT '{}',
    exploit_available        bool        NOT NULL DEFAULT false,
    in_cisa_kev              bool        NOT NULL DEFAULT false,
    epss_score               float8,                            -- excluded from material_hash (§5.3)
    date_epss_updated        timestamptz,
    material_hash            text                               -- sha256(jcs(material_fields)), populated on first merge
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_severity_idx
    ON cves (severity);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_in_cisa_kev_idx
    ON cves (in_cisa_kev);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_exploit_available_idx
    ON cves (exploit_available);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_modified_canonical_idx
    ON cves (date_modified_canonical DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_epss_updated_idx
    ON cves (date_epss_updated);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_published_idx
    ON cves (date_published);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_cwe_ids_idx
    ON cves USING gin (cwe_ids);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_description_trgm_idx
    ON cves USING gin (description_primary gin_trgm_ops);

-- ============================================================
-- cve_search_index: isolated tsvector FTS (1:1 with cves).
-- Separate table prevents GIN write amplification on cves (§8.1).
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_search_index (
    cve_id       text      PRIMARY KEY REFERENCES cves(cve_id) ON DELETE CASCADE,
    fts_document tsvector  NOT NULL
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_search_index_fts_idx
    ON cve_search_index USING gin (fts_document);

-- ============================================================
-- cve_sources: per-feed normalized representation of a CVE.
-- The merge pipeline re-reads all rows for a CVE on every ingest
-- and resolves per-field precedence (§5.1).
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_sources (
    cve_id               text        NOT NULL,
    source_name          text        NOT NULL,
    -- Native feed advisory ID (e.g., GHSA-xxxx, RUSTSEC-yyyy) when alias
    -- resolution promoted a CVE alias to the cve_id PK. NULL for feeds
    -- where cve_id IS the native ID (NVD, MITRE).
    source_id            text,
    -- Application upsert: ON CONFLICT DO UPDATE SET normalized_json = EXCLUDED.normalized_json
    --   WHERE cve_sources.normalized_json IS DISTINCT FROM EXCLUDED.normalized_json
    normalized_json      jsonb       NOT NULL,
    source_date_modified timestamptz,
    source_url           text,
    ingested_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, source_name)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_sources_source_name_idx
    ON cve_sources (source_name);

-- Required for FindCVEBySourceID used in late-binding PK migration (§3.2).
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_sources_source_id_idx
    ON cve_sources (source_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_sources_source_date_modified_idx
    ON cve_sources (source_date_modified);

-- ============================================================
-- cve_raw_payloads: full feed payloads for audit/reprocessing.
-- Pruned by the daily retention job (PLAN.md §21).
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_raw_payloads (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id      text        NOT NULL,
    source_name text        NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now(),
    payload     jsonb       NOT NULL
);

-- Autovacuum tuning: insert-heavy, periodic bulk-delete by retention job.
ALTER TABLE cve_raw_payloads SET (
    autovacuum_vacuum_scale_factor = 0.01,
    autovacuum_vacuum_cost_delay   = 2,
    fillfactor                     = 80
);

-- Supports retention cleanup (§21) and per-CVE audit queries.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_raw_payloads_lookup_idx
    ON cve_raw_payloads (cve_id, source_name, ingested_at DESC);

-- ============================================================
-- cve_references: external URLs associated with a CVE.
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_references (
    id            uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id        text    NOT NULL,
    url           text    NOT NULL,
    url_canonical text    NOT NULL,
    tags          text[]  NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_references_cve_url_uq
    ON cve_references (cve_id, url_canonical);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_references_cve_id_idx
    ON cve_references (cve_id);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_references_url_canonical_idx
    ON cve_references (url_canonical);

-- ============================================================
-- cve_affected_packages: ecosystem/package version range data.
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_affected_packages (
    id            uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id        text    NOT NULL,
    ecosystem     text    NOT NULL,
    package_name  text    NOT NULL,
    namespace     text,
    range_type    text,
    introduced    text,
    fixed         text,
    last_affected text,
    events        jsonb   -- raw OSV events array, no IS DISTINCT FROM needed (child table always delete+re-insert)
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_eco_pkg_idx
    ON cve_affected_packages (ecosystem, package_name);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_cve_id_idx
    ON cve_affected_packages (cve_id);

-- ============================================================
-- cve_affected_cpes: CPE strings linked to a CVE.
-- ============================================================
CREATE TABLE IF NOT EXISTS cve_affected_cpes (
    id             uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id         text    NOT NULL,
    cpe            text    NOT NULL,
    cpe_normalized text    NOT NULL
);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cve_cpe_uq
    ON cve_affected_cpes (cve_id, cpe_normalized);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cpe_normalized_idx
    ON cve_affected_cpes (cpe_normalized);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cve_id_idx
    ON cve_affected_cpes (cve_id);

-- ============================================================
-- epss_staging: holds EPSS scores for CVEs not yet ingested.
-- Applied and deleted during merge pipeline on next CVE upsert
-- (two-statement EPSS pattern, §5.3).
-- ============================================================
CREATE TABLE IF NOT EXISTS epss_staging (
    cve_id      text    PRIMARY KEY,
    epss_score  float8  NOT NULL,
    as_of_date  date    NOT NULL,
    ingested_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS epss_staging_ingested_at_idx
    ON epss_staging (ingested_at);
