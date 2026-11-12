# Long CPEs and package names no longer fail the merge

## What was built

- The digest function from migration 000060 is now named `text_key_digest(text)`, so any unbounded text key that needs only equality can use it. Before, it was named for reference URLs. The rename was made on the long-reference-URL branch (PR #224) before that PR merged.
- Migration 000061 (`bounded_cpe_and_package_keys`):
  - `cve_affected_cpes_cve_cpe_digest_uq` on `(cve_id, text_key_digest(cpe_normalized))` replaces `cve_affected_cpes_cve_cpe_uq`, and `InsertAffectedCPE` names that expression in its `ON CONFLICT` target.
  - `cve_cpe_matches_check_idx` is rebuilt on `left(cpe_normalized, 512) COLLATE "C"`.
  - `cve_affected_cpes_cpe_normalized_idx` and `cve_affected_packages_eco_pkg_idx` are dropped.
- The merge leaves out an affected package whose name is over 1,024 bytes (`maxIndexedPackageNameBytes` in `internal/merge/pipeline.go`) and logs a warning with the CVE, the ecosystem and the name's length.
- New tests in `internal/merge/pipeline_integration_test.go`:
  - `TestIngest_LongCPEIsStored` merges a long CPE into both `cve_affected_cpes` and `cve_cpe_matches`.
  - `TestInsertAffectedCPE_LongDuplicateIsIgnored` shows that the digest index still ignores a duplicate long CPE.
  - `TestIngest_LongPackageNameIsLeftOut` checks that the long entry is left out, the other entry is stored, and the warning is logged.
- Documentation:
  - PLAN.md Appendix A: `cve_affected_packages`, `cve_affected_cpes` and `cve_cpe_matches`.
  - DB-26 in `dev/implementation-pitfalls.md` (btree index over unbounded feed text).
  - The version check endpoint design (section 9, index use, and section 13) and plan (Task 3.9's CPE statement, `CPEKey`, its tests, the Phase 4 measurements, and a Discoveries entry).

## Why

The audit for the long-reference-URL fix found three more columns that the btree row limit (2,704 bytes) could break: `cve_affected_packages.package_name`, `cve_affected_cpes.cpe_normalized` and `cve_cpe_matches.cpe_normalized`. Nothing in the code bounds their length. Real data had not reached the limit, but one malformed feed record would fail the merge of its CVE and stop its feed job on every run, as Red Hat's long reference did.

## Decisions and gotchas

- **Decided by Sam: CPEs are stored in full, and long package names are left out.** The two columns are matched differently:
  - Watchlist CPEs (up to 512 characters) and the version check's CPE lookups match by prefix. So a malformed long CPE that starts with a real vendor and product can still match, and leaving it out could hide a match.
  - Package names are matched on the exact folded name. Watchlist names are capped at 255 characters, so nothing can match a name over 1,024 bytes, and no registry allows one. Indexing a prefix of the name instead would have made every package query apply the same `left()` expression. A query that left it out would scan the whole table without any error.
- **Why 1,024 bytes and not 2,048.** `cve_affected_packages_check_idx` indexes the folded name, and `lower()` can make text longer: `Ⱥ` (2 bytes) becomes `ⱥ` (3 bytes). A 2,048-byte name could fold to over 3,000 bytes. 1,024 leaves room for that and for the ecosystem in the same index row.
- **The long package name is still in `material_hash` and the search index.** The merge leaves the entry out only where it inserts rows, which is where the index limit applies. The hash and the search document come from the resolved data. `to_tsvector` skips a word longer than 2,047 characters with a notice, not an error, and `TestIngest_LongPackageNameIsLeftOut` merges an 8,192-byte name without an error.
- **Why `left(cpe_normalized, 512)` keeps prefix scans working.** If a value starts with a prefix of 512 characters or fewer, its first 512 characters start with that prefix too, so a range scan on the key finds every candidate. 512 characters are at most 2,048 bytes. For a longer prefix, the query cuts its bounds to 512 characters and checks the whole value with `starts_with`. `EXPLAIN` on the migrated schema (`enable_seqscan = off`) showed a Bitmap Index Scan on `cve_cpe_matches_check_idx` with the range as its Index Cond and `starts_with` as a Filter. No code reads this index yet. Phase 3 of the version check endpoint will, and its plan was updated before any code exists.
- **Dropped indexes.**
  - `cve_affected_cpes_cpe_normalized_idx`: watchlist matching compares `cac.cpe_normalized LIKE (wi.cpe_normalized || '%')`. A btree can serve `LIKE` only with a constant pattern on a C-collated column.
  - `cve_affected_packages_eco_pkg_idx`: every package query compares `lower()` or the folded name, never the raw name, and every current query finds rows by `cve_id`.
  - Both were write cost on every merge. The package test first failed on `eco_pkg_idx`: an index no query reads still fails the insert.
- **Down migration** rebuilds the full-value indexes. That fails while a stored CPE is over the limit, as its comment says.

## Quality checks

- The three new tests failed first with `index row size ... exceeds btree version 4 maximum 2704`, on `cve_affected_cpes_cve_cpe_uq` and `cve_affected_packages_eco_pkg_idx`. They pass after the change, with the long-reference and long-CNA tests.
- Migration 000061 down and up were run against a test database with a statement runner that splits each file on `;`, as golang-migrate does. Down restored the four original index definitions. Up restored the new ones.
- `golangci-lint` v2.15.0 on `./internal/merge/...` and `./internal/store/...`: 0 issues.
- Full suite: see the PR.
