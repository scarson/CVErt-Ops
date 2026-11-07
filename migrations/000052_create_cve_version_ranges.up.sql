-- migrate:no-transaction

-- cve_cpe_matches: one row per NVD configurations cpeMatch entry.
-- cve_affected_cpes keeps one row per CPE string and feeds material_hash, so it
-- cannot hold ranges: NVD repeats one criteria string with a different range per
-- release branch. vulnerable = false marks a "running on" platform CPE.
--
-- Rows are deleted and re-inserted on every merge under the per-CVE advisory lock,
-- and the merge pipeline removes duplicates, so no unique index is needed. Version
-- strings are unbounded upstream input and could exceed the btree row limit.
--
-- The foreign key is deferred because the late-binding CVE ID move updates child
-- tables before it updates cves.
CREATE TABLE IF NOT EXISTS cve_cpe_matches (
    id                      uuid    PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id                  text    NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    cpe                     text    NOT NULL,
    cpe_normalized          text    NOT NULL,
    version_start_including text,
    version_start_excluding text,
    version_end_including   text,
    version_end_excluding   text,
    vulnerable              boolean NOT NULL
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_cve_id_idx
    ON cve_cpe_matches (cve_id);

-- cve_cna_affected: one row per CVE 5 containers.cna.affected[] entry, which is the
-- only product and version data for a CVE NVD has not analysed. Fields are stored as
-- the CNA sent them. CVE 5 allows product up to 2048 characters, version up to 1024,
-- and CNAs repeat entries, so the merge pipeline removes duplicates rather than a
-- unique index. default_status has no CHECK: a CNA value outside the CVE 5 enum must
-- not fail the merge of the whole CVE.
--
-- versions holds the CVE 5 versions[] array. Child rows are always deleted and
-- re-inserted, so no IS DISTINCT FROM guard applies.
CREATE TABLE IF NOT EXISTS cve_cna_affected (
    id             uuid  PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id         text  NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    vendor         text,
    product        text,
    package_name   text,
    collection_url text,
    default_status text,
    versions       jsonb NOT NULL DEFAULT '[]'
);

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cna_affected_cve_id_idx
    ON cve_cna_affected (cve_id);

-- Global corpus tables: no org_id and no RLS. UPDATE is for the late-binding CVE ID move.
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_cpe_matches TO cvert_ops_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON cve_cna_affected TO cvert_ops_app;
