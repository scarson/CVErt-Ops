-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.

-- A CPE has no length bound, and a btree row holds at most 2,704 bytes, so a long
-- CPE would fail the merge of its CVE and stop the feed job. CPEs are stored in
-- full, because a watchlist matches them by prefix and a long CPE can still match.
-- The merge leaves out package names too long to index (maxIndexedPackageNameBytes
-- in internal/merge), so the package indexes need no change here.

-- InsertAffectedCPE names this expression in its ON CONFLICT target.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_affected_cpes_cve_cpe_digest_uq
    ON cve_affected_cpes (cve_id, text_key_digest(cpe_normalized));

DROP INDEX CONCURRENTLY IF EXISTS cve_affected_cpes_cve_cpe_uq;

-- No query can use this index. Watchlist matching compares with LIKE against a
-- pattern built from another column, which a btree cannot serve.
DROP INDEX CONCURRENTLY IF EXISTS cve_affected_cpes_cpe_normalized_idx;

-- No query can use this index. Every package query compares the folded name
-- (cve_affected_packages_check_idx) or finds rows by cve_id.
DROP INDEX CONCURRENTLY IF EXISTS cve_affected_packages_eco_pkg_idx;

-- The version check endpoint reads CPE matches by prefix range. The first 512
-- characters are at most 2,048 bytes, and every value that starts with a prefix of
-- 512 characters or fewer has a key that starts with it too, so a range scan on the
-- key finds every candidate. Queries also compare the full value.
DROP INDEX CONCURRENTLY IF EXISTS cve_cpe_matches_check_idx;

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_cpe_matches_check_idx
    ON cve_cpe_matches ((left(cpe_normalized, 512) COLLATE "C"));
