-- migrate:no-transaction

-- The version check endpoint finds rows by exact package, by CPE prefix and by CNA
-- name. package_key is the CNA packageURL mapped to the identity a package request
-- uses, and is NULL when the entry has none or the URL is refused.
ALTER TABLE cve_cna_affected ADD COLUMN IF NOT EXISTS package_key text;

-- Matches ecosystem.FoldedNameSQL, which builds the query's expression.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_packages_check_idx
    ON cve_affected_packages (ecosystem,
        (CASE WHEN ecosystem = 'PyPI' THEN regexp_replace(lower(package_name), '[-_.]+', '-', 'g') ELSE lower(package_name) END));

-- C collation so a range on the CPE prefix can use the index whatever the database collation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((cpe_normalized COLLATE "C"));

-- left(..., 256): vendor and product can reach 2,048 characters, and a value over the
-- btree row limit would fail the merge of the whole CVE.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_check_idx
    ON cve_cna_affected ((left(lower(vendor), 256) COLLATE "C"), (left(lower(product), 256) COLLATE "C"));

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_package_key_idx
    ON cve_cna_affected (package_key) WHERE package_key IS NOT NULL;
