-- name: UpsertCVE :exec
INSERT INTO cves (
    cve_id, status, date_published, date_modified_source_max,
    date_modified_canonical, date_first_seen, description_primary,
    severity, cvss_v3_score, cvss_v3_vector, cvss_v3_source,
    cvss_v4_score, cvss_v4_vector, cvss_v4_source, cvss_score_diverges,
    cwe_ids, exploit_available, in_cisa_kev, material_hash,
    match_inputs_hash, date_match_inputs_changed
)
VALUES (
    $1, $2, $3, $4,
    $5, now(), $6,
    $7, $8, $9, $10,
    $11, $12, $13, $14,
    $15, $16, $17, $18,
    $19, $5
)
ON CONFLICT (cve_id) DO UPDATE
    SET status                   = EXCLUDED.status,
        date_published           = EXCLUDED.date_published,
        date_modified_source_max = EXCLUDED.date_modified_source_max,
        -- Only bump date_modified_canonical on material changes (triggers alert eval).
        date_modified_canonical  = CASE
            WHEN cves.material_hash IS DISTINCT FROM EXCLUDED.material_hash
            THEN EXCLUDED.date_modified_canonical
            ELSE cves.date_modified_canonical
        END,
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
        material_hash            = EXCLUDED.material_hash,
        -- Stamp a change to the rule match inputs outside material_hash (re-checks
        -- the CVE without firing unrelated rules). A stored NULL counts as changed.
        date_match_inputs_changed = CASE
            WHEN cves.match_inputs_hash IS DISTINCT FROM EXCLUDED.match_inputs_hash
            THEN EXCLUDED.date_modified_canonical
            ELSE cves.date_match_inputs_changed
        END,
        match_inputs_hash        = EXCLUDED.match_inputs_hash;

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
ON CONFLICT (cve_id, source_name, source_id) DO UPDATE
    SET normalized_json      = EXCLUDED.normalized_json,
        source_date_modified = EXCLUDED.source_date_modified,
        source_url           = EXCLUDED.source_url,
        ingested_at          = now()
    WHERE cve_sources.normalized_json IS DISTINCT FROM EXCLUDED.normalized_json;

-- name: GetAllCVESources :many
SELECT * FROM cve_sources WHERE cve_id = $1 ORDER BY source_name, source_id;

-- name: FindCVEBySourceID :one
-- Finds where an advisory is stored other than under the CVE it now names, for
-- late-binding migration (§3.2).
SELECT cve_id FROM cve_sources
WHERE source_name = $1 AND source_id = $2 AND cve_id <> $3
ORDER BY cve_id LIMIT 1;

-- name: DeleteCVESource :exec
DELETE FROM cve_sources WHERE cve_id = $1 AND source_name = $2 AND source_id = $3;

-- name: CountCVESources :one
SELECT count(*) FROM cve_sources WHERE cve_id = $1;

-- name: DeleteCVEReferences :exec
-- Delete all reference rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_references WHERE cve_id = $1;

-- name: DeleteCVEAffectedPackages :exec
-- Delete all affected-package rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_affected_packages WHERE cve_id = $1;

-- name: DeleteCVEAffectedCPEs :exec
-- Delete all CPE rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_affected_cpes WHERE cve_id = $1;

-- name: DeleteCVECPEMatches :exec
-- Delete all CPE match rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_cpe_matches WHERE cve_id = $1;

-- name: DeleteCVECNAAffected :exec
-- Delete all CNA affected rows before re-inserting in merge pipeline (§5.1).
DELETE FROM cve_cna_affected WHERE cve_id = $1;

-- name: InsertCVERawPayload :exec
INSERT INTO cve_raw_payloads (cve_id, source_name, payload)
VALUES ($1, $2, $3);

-- name: InsertCVEReference :exec
INSERT INTO cve_references (cve_id, url, url_canonical, tags)
VALUES ($1, $2, $3, $4)
ON CONFLICT (cve_id, text_key_digest(url_canonical)) DO NOTHING;

-- name: InsertAffectedPackage :exec
INSERT INTO cve_affected_packages (
    cve_id, ecosystem, package_name, namespace,
    range_type, introduced, fixed, last_affected, events
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: InsertAffectedCPE :exec
INSERT INTO cve_affected_cpes (cve_id, cpe, cpe_normalized)
VALUES ($1, $2, $3)
ON CONFLICT (cve_id, text_key_digest(cpe_normalized)) DO NOTHING;

-- name: InsertCPEMatch :exec
INSERT INTO cve_cpe_matches (
    cve_id, cpe, cpe_normalized,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    vulnerable
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: InsertCNAAffected :exec
INSERT INTO cve_cna_affected (
    cve_id, vendor, product, package_name, collection_url, default_status, versions, package_key
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

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

-- name: ListCVEIDsAfter :many
-- Keyset page of CVE IDs for full-corpus walks (search index rebuild).
SELECT cve_id FROM cves
WHERE cve_id > @after_cve_id::text
ORDER BY cve_id
LIMIT @batch_size;

-- name: LockCVEAdvisoryKeys :exec
-- Takes the per-CVE merge advisory lock (merge.CVEAdvisoryKey) for every key,
-- in ascending key order, until the transaction ends.
SELECT pg_advisory_xact_lock(k)
FROM (SELECT unnest(@keys::bigint[]) AS k ORDER BY k) AS ordered;

-- name: ListSearchIndexInputs :many
-- The fields UpsertCVESearchIndex builds the tsvector from, for a batch of
-- CVEs. Package names come back unordered and may repeat; the caller
-- de-duplicates and sorts them bytewise, as the merge pipeline does, because
-- an ORDER BY here would follow the database collation.
SELECT c.cve_id,
       c.description_primary,
       c.cwe_ids,
       COALESCE(
           array_agg(p.package_name) FILTER (WHERE p.package_name IS NOT NULL),
           '{}'
       )::text[] AS package_names
FROM cves c
LEFT JOIN cve_affected_packages p ON p.cve_id = c.cve_id
WHERE c.cve_id = ANY(@cve_ids::text[])
GROUP BY c.cve_id
ORDER BY c.cve_id;

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

-- name: UpdateCVEEPSSBatch :exec
-- Two-statement EPSS pattern step 1 for a batch: update each live CVE row whose
-- score changed. cve_ids[i] pairs with epss_scores[i]; cve_ids must not repeat.
UPDATE cves AS c
SET epss_score = s.epss_score, date_epss_updated = now()
FROM (
    SELECT unnest(@cve_ids::text[]) AS cve_id,
           unnest(@epss_scores::double precision[]) AS epss_score
) AS s
WHERE c.cve_id = s.cve_id AND c.epss_score IS DISTINCT FROM s.epss_score;

-- name: UpsertEPSSStagingBatch :exec
-- Two-statement EPSS pattern step 2 for a batch: stage each score whose CVE does
-- not yet exist in cves. Same guards as UpsertEPSSStaging; cve_ids must not
-- repeat, because ON CONFLICT DO UPDATE cannot change one row twice.
INSERT INTO epss_staging (cve_id, epss_score, as_of_date)
SELECT s.cve_id, s.epss_score, @as_of_date::date
FROM (
    SELECT unnest(@cve_ids::text[]) AS cve_id,
           unnest(@epss_scores::double precision[]) AS epss_score
) AS s
WHERE NOT EXISTS (SELECT 1 FROM cves WHERE cves.cve_id = s.cve_id)
ON CONFLICT (cve_id) DO UPDATE
    SET epss_score  = EXCLUDED.epss_score,
        as_of_date  = EXCLUDED.as_of_date,
        ingested_at = now()
    WHERE epss_staging.epss_score IS DISTINCT FROM EXCLUDED.epss_score;

-- name: GetCVEReferences :many
SELECT * FROM cve_references WHERE cve_id = $1 ORDER BY url_canonical;

-- name: GetCVEAffectedPackages :many
SELECT * FROM cve_affected_packages WHERE cve_id = $1 ORDER BY ecosystem, package_name;

-- name: GetCVEAffectedCPEs :many
SELECT * FROM cve_affected_cpes WHERE cve_id = $1 ORDER BY cpe_normalized;

-- name: GetCVEVulnerableCPEMatches :many
-- CPE matches for what a CVE affects: skips "running on" platform CPEs.
SELECT * FROM cve_cpe_matches
WHERE cve_id = $1 AND vulnerable
ORDER BY cpe_normalized, version_start_including, version_start_excluding,
         version_end_including, version_end_excluding;

-- name: GetCVECNAAffected :many
SELECT * FROM cve_cna_affected
WHERE cve_id = $1
ORDER BY vendor, product, package_name, collection_url, default_status, versions::text;

-- name: GetCVESnapshot :one
-- Returns the fields needed for alert delivery payloads.
SELECT cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
       description_primary, exploit_available, in_cisa_kev, status
FROM cves WHERE cve_id = $1;

-- name: DigestCVEs :many
-- Fetch CVEs modified since $1, optionally filtered by severity, leaving out the
-- CVE versions in $3: a JSON array of {"cve_id", "date_modified_canonical"}
-- objects a previous digest of the report already sent.
-- Sort: severity desc (critical > high > medium > low), CVSS v3 tiebreaker.
-- total_count is the number of matching CVEs before LIMIT, so callers can tell
-- when the limit cut the result short. A window function keeps that count on the
-- same predicate and snapshot as the rows, at the cost of buffering every
-- matching row before the sort.
SELECT cve_id, severity, cvss_v3_score, cvss_v4_score, epss_score,
       description_primary, exploit_available, in_cisa_kev, date_modified_canonical,
       count(*) OVER () AS total_count
FROM cves
WHERE date_modified_canonical > $1
  AND COALESCE(lower(status), '') NOT IN ('rejected', 'withdrawn')
  AND ($2::text[] IS NULL OR lower(severity) = ANY($2::text[]))
  AND NOT EXISTS (
      SELECT 1
      FROM jsonb_to_recordset($3::jsonb) AS sent(cve_id text, date_modified_canonical timestamptz)
      WHERE sent.cve_id = cves.cve_id
        AND sent.date_modified_canonical = cves.date_modified_canonical
  )
ORDER BY
    CASE lower(severity)
        WHEN 'critical' THEN 1
        WHEN 'high'     THEN 2
        WHEN 'medium'   THEN 3
        WHEN 'low'      THEN 4
        ELSE 5
    END,
    cvss_v3_score DESC NULLS LAST
LIMIT 500;

-- name: ListCVEs :many
-- Base list query — dynamic WHERE and ORDER BY built by squirrel in the
-- store layer. This static query handles the no-filter paginated case.
SELECT c.*
FROM cves c
ORDER BY c.date_modified_canonical DESC, c.cve_id
LIMIT $1 OFFSET $2;
