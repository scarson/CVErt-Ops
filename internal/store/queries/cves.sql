-- name: UpsertCVE :exec
INSERT INTO cves (
    cve_id, status, date_published, date_modified_source_max,
    date_modified_canonical, date_first_seen, description_primary,
    severity, cvss_v3_score, cvss_v3_vector, cvss_v3_source,
    cvss_v4_score, cvss_v4_vector, cvss_v4_source, cvss_score_diverges,
    cwe_ids, exploit_available, in_cisa_kev, material_hash
)
VALUES (
    $1, $2, $3, $4,
    $5, now(), $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14,
    $15, $16, $17, $18
)
ON CONFLICT (cve_id) DO UPDATE
    SET status                   = EXCLUDED.status,
        date_published           = EXCLUDED.date_published,
        date_modified_source_max = EXCLUDED.date_modified_source_max,
        date_modified_canonical  = EXCLUDED.date_modified_canonical,
        description_primary      = EXCLUDED.description_primary,
        severity                 = EXCLUDED.severity,
        cvss_v3_score            = EXCLUDED.cvss_v3_score,
        cvss_v3_vector           = EXCLUDED.cvss_v3_vector,
        cvss_v3_source           = EXCLUDED.cvss_v3_source,
        cvss_v4_score            = EXCLUDED.cvss_v4_score,
        cvss_v4_vector           = EXCLUDED.cvss_v4_vector,
        cvss_v4_source           = EXCLUDED.cvss_v4_source,
        cvss_score_diverges      = EXCLUDED.cvss_score_diverges,
        cwe_ids                  = EXCLUDED.cwe_ids,
        exploit_available        = EXCLUDED.exploit_available,
        in_cisa_kev              = EXCLUDED.in_cisa_kev,
        material_hash            = EXCLUDED.material_hash
    WHERE cves.material_hash IS DISTINCT FROM EXCLUDED.material_hash;

-- name: GetCVE :one
SELECT * FROM cves WHERE cve_id = $1;

-- name: TombstoneCVE :exec
-- Null out all computed fields for a rejected/withdrawn CVE (§5.1 tombstone).
UPDATE cves
SET
    cvss_v3_score   = NULL,
    cvss_v3_vector  = NULL,
    cvss_v3_source  = NULL,
    cvss_v4_score   = NULL,
    cvss_v4_vector  = NULL,
    cvss_v4_source  = NULL,
    epss_score      = NULL,
    exploit_available = false,
    in_cisa_kev     = false
WHERE cve_id = $1;

-- name: UpsertCVESource :exec
INSERT INTO cve_sources (cve_id, source_name, source_id, normalized_json, source_date_modified, source_url)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (cve_id, source_name) DO UPDATE
    SET source_id            = EXCLUDED.source_id,
        normalized_json      = EXCLUDED.normalized_json,
        source_date_modified = EXCLUDED.source_date_modified,
        source_url           = EXCLUDED.source_url,
        ingested_at          = now()
    WHERE cve_sources.normalized_json IS DISTINCT FROM EXCLUDED.normalized_json;

-- name: GetAllCVESources :many
SELECT * FROM cve_sources WHERE cve_id = $1 ORDER BY source_name;

-- name: FindCVEBySourceID :one
-- Used for late-binding PK migration: find a CVE row stored under its native
-- GHSA/OSV ID when a CVE alias has since been added (§3.2).
SELECT cve_id FROM cve_sources WHERE source_name = $1 AND source_id = $2 LIMIT 1;

-- name: DeleteCVEReferences :exec
-- Delete all reference rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_references WHERE cve_id = $1;

-- name: DeleteCVEAffectedPackages :exec
-- Delete all affected-package rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_affected_packages WHERE cve_id = $1;

-- name: DeleteCVEAffectedCPEs :exec
-- Delete all CPE rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_affected_cpes WHERE cve_id = $1;

-- name: InsertCVERawPayload :exec
INSERT INTO cve_raw_payloads (cve_id, source_name, payload)
VALUES ($1, $2, $3);

-- name: InsertCVEReference :exec
INSERT INTO cve_references (cve_id, url, url_canonical, tags)
VALUES ($1, $2, $3, $4)
ON CONFLICT (cve_id, url_canonical) DO NOTHING;

-- name: InsertAffectedPackage :exec
INSERT INTO cve_affected_packages (
    cve_id, ecosystem, package_name, namespace,
    range_type, introduced, fixed, last_affected, events
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: InsertAffectedCPE :exec
INSERT INTO cve_affected_cpes (cve_id, cpe, cpe_normalized)
VALUES ($1, $2, $3)
ON CONFLICT (cve_id, cpe_normalized) DO NOTHING;

-- name: UpsertCVESearchIndex :exec
-- Weights: A=description (highest), B=CWE names, C=package names, D=CVE ID.
INSERT INTO cve_search_index (cve_id, fts_document)
VALUES (
    @cve_id,
    setweight(to_tsvector('english', coalesce(@description::text, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(@cwe_names::text, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(@package_names::text, '')), 'C') ||
    setweight(to_tsvector(@cve_id::text), 'D')
)
ON CONFLICT (cve_id) DO UPDATE
    SET fts_document = EXCLUDED.fts_document
    WHERE cve_search_index.fts_document IS DISTINCT FROM EXCLUDED.fts_document;

-- name: UpsertEPSSStaging :exec
-- Two-statement EPSS pattern step 2 (pitfall §2.5/§2.6): insert staging row ONLY
-- if the CVE does not yet exist in cves. DB-side WHERE NOT EXISTS eliminates the
-- TOCTOU race and avoids application-side RowsAffected branching. Both this
-- statement and UpdateCVEEPSS run unconditionally for every CSV row.
INSERT INTO epss_staging (cve_id, epss_score, as_of_date)
SELECT t.cve_id, t.epss_score, t.as_of_date
FROM (VALUES ($1::text, $2::double precision, $3::date)) AS t(cve_id, epss_score, as_of_date)
WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cve_id = t.cve_id)
ON CONFLICT (cve_id) DO UPDATE
    SET epss_score  = EXCLUDED.epss_score,
        as_of_date  = EXCLUDED.as_of_date,
        ingested_at = now()
    WHERE epss_staging.epss_score IS DISTINCT FROM EXCLUDED.epss_score;

-- name: GetEPSSStaging :one
SELECT * FROM epss_staging WHERE cve_id = $1;

-- name: DeleteEPSSStaging :exec
DELETE FROM epss_staging WHERE cve_id = $1;

-- name: UpdateCVEEPSS :exec
-- Two-statement EPSS pattern step 1: update live CVE row if score changed.
UPDATE cves
SET epss_score = $2, date_epss_updated = now()
WHERE cve_id = $1 AND epss_score IS DISTINCT FROM $2;

-- name: GetCVEReferences :many
SELECT * FROM cve_references WHERE cve_id = $1 ORDER BY url_canonical;

-- name: GetCVEAffectedPackages :many
SELECT * FROM cve_affected_packages WHERE cve_id = $1 ORDER BY ecosystem, package_name;

-- name: GetCVEAffectedCPEs :many
SELECT * FROM cve_affected_cpes WHERE cve_id = $1 ORDER BY cpe_normalized;

-- name: GetCVESnapshot :one
-- Returns the fields needed for alert delivery payloads.
SELECT cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
       description_primary, exploit_available, in_cisa_kev
FROM cves WHERE cve_id = $1;

-- name: ListCVEs :many
-- Base list query — dynamic WHERE and ORDER BY built by squirrel in the
-- store layer. This static query handles the no-filter paginated case.
SELECT c.*
FROM cves c
ORDER BY c.date_modified_canonical DESC, c.cve_id
LIMIT $1 OFFSET $2;
