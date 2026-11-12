-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.
-- The plain indexes cannot be built while a stored canonical URL is over the btree
-- row limit, so delete such references before migrating down.

CREATE INDEX CONCURRENTLY IF NOT EXISTS cve_references_url_canonical_idx
    ON cve_references (url_canonical);

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS cve_references_cve_url_uq
    ON cve_references (cve_id, url_canonical);

DROP INDEX CONCURRENTLY IF EXISTS cve_references_cve_url_digest_uq;

DROP FUNCTION IF EXISTS text_key_digest(text);
