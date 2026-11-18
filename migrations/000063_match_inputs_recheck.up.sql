-- migrate:no-transaction
-- CREATE INDEX CONCURRENTLY cannot run inside a transaction block (pitfall 11.2).
-- The migration runner executes each statement of this file in its own autocommit.

-- Alert rules match on CNA vendor and product names and on the vulnerable flag of
-- NVD CPE matches, which are not material_hash inputs. The merge hashes them into
-- match_inputs_hash and stamps date_match_inputs_changed with its clock when the
-- hash changes, so realtime and batch evaluation re-check the CVE without moving
-- material_hash or date_modified_canonical. A NULL hash has never been computed
-- and counts as changed, so each CVE is re-checked once on its first merge here.
-- Both columns are nullable with no default, so adding them rewrites no rows.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS match_inputs_hash text;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS date_match_inputs_changed timestamptz;

-- The batch evaluator's candidate scan reads CVEs stamped after its cursor.
CREATE INDEX CONCURRENTLY IF NOT EXISTS cves_date_match_inputs_changed_idx
    ON cves (date_match_inputs_changed)
    WHERE date_match_inputs_changed IS NOT NULL;
