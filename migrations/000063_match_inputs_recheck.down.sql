-- migrate:no-transaction
-- DROP INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.

DROP INDEX CONCURRENTLY IF EXISTS cves_date_match_inputs_changed_idx;

ALTER TABLE cves DROP COLUMN IF EXISTS date_match_inputs_changed;
ALTER TABLE cves DROP COLUMN IF EXISTS match_inputs_hash;
