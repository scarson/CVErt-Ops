-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.

-- A reference URL has no length bound, and a btree row holds at most 2,704 bytes,
-- so a long URL failed the merge of its CVE and stopped the feed job (Red Hat sends
-- one over 3,000 bytes for CVE-2006-4339). Uniqueness is enforced on a SHA-256
-- digest of the canonical URL instead, which is 32 bytes whatever the URL's length.
--
-- sha256(text::bytea) would parse backslashes as bytea escapes, and convert_to is
-- STABLE, so it cannot appear in an index expression by itself. The database
-- encoding is fixed for the life of a database, so this function is immutable in
-- practice. md5(text) is IMMUTABLE but can fail on a server whose OpenSSL runs in
-- FIPS mode. The SQL-standard body is parsed when the function is created, so
-- search_path cannot redirect it later.
CREATE OR REPLACE FUNCTION reference_url_digest(url text) RETURNS bytea
    LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
    RETURN sha256(convert_to(url, 'UTF8'));

-- InsertCVEReference names this expression in its ON CONFLICT target.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_references_cve_url_digest_uq
    ON cve_references (cve_id, reference_url_digest(url_canonical));

DROP INDEX CONCURRENTLY IF EXISTS cve_references_cve_url_uq;

-- Nothing looks references up by URL alone, and this index has the same row limit.
DROP INDEX CONCURRENTLY IF EXISTS cve_references_url_canonical_idx;
