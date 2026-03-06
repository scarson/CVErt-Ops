-- name: UpsertVendorEnrichment :exec
-- ABOUTME: Upserts vendor-specific CVE enrichment data.
-- ABOUTME: IS DISTINCT FROM guard prevents dead tuples on no-op updates.
INSERT INTO cve_vendor_enrichment (
    cve_id, source_name, vendor_severity, vendor_fix_state, enrichment
)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (cve_id, source_name) DO UPDATE
    SET vendor_severity  = EXCLUDED.vendor_severity,
        vendor_fix_state = EXCLUDED.vendor_fix_state,
        enrichment       = EXCLUDED.enrichment,
        updated_at       = now()
    WHERE cve_vendor_enrichment.enrichment IS DISTINCT FROM EXCLUDED.enrichment
       OR cve_vendor_enrichment.vendor_severity IS DISTINCT FROM EXCLUDED.vendor_severity
       OR cve_vendor_enrichment.vendor_fix_state IS DISTINCT FROM EXCLUDED.vendor_fix_state;

-- name: GetVendorEnrichment :one
SELECT * FROM cve_vendor_enrichment
WHERE cve_id = $1 AND source_name = $2;

-- name: ListVendorEnrichmentByCVE :many
SELECT * FROM cve_vendor_enrichment
WHERE cve_id = $1
ORDER BY source_name;
