# Long reference URLs no longer fail the merge

## What was built

- Migration 000060 adds `text_key_digest(text)`, an IMMUTABLE SQL function that returns the SHA-256 of a URL. The unique index `cve_references_cve_url_digest_uq` on `(cve_id, text_key_digest(url_canonical))` replaces `cve_references_cve_url_uq` on `(cve_id, url_canonical)`. The migration also drops `cve_references_url_canonical_idx`.
- `InsertCVEReference` names the digest expression in its `ON CONFLICT` target.
- New tests in `internal/merge/pipeline_integration_test.go`:
  - `TestIngest_LongReferenceURLIsStored` merges a record with an over-long reference.
  - `TestInsertCVEReference_LongDuplicateIsIgnored` shows that the index still ignores a second row with the same long URL.
- Documentation:
  - PLAN.md Appendix A (`cve_references`) describes the new index.
  - `dev/implementation-pitfalls.md` has a new entry, DB-26 (btree index over unbounded feed text), and a §2 checklist item.
  - `dev/testing-pitfalls.md` §9 has an item on testing long values in btree-indexed columns.

## Why

Red Hat had failed on every run of the full ingest: 11 consecutive failures in `feed_sync_state`, and never a success. Each run stopped at CVE-2006-4339 with `merge: insert reference: ERROR: index row size 3168 exceeds btree version 4 maximum 2704 for index "cve_references_cve_url_uq"`. A btree row holds at most 2,704 bytes after PostgreSQL compresses the key. One Red Hat reference URL for that CVE is longer than that, and nothing bounds a reference URL's length. The failed insert rolls back the CVE's merge, the feed job stops at the same record every time, and its cursor never advances.

## Decisions and gotchas

- **Stored data and `material_hash` are unchanged.** References are not in `MaterialFields` (`internal/merge/hash.go`). Every URL is stored in full, and none is truncated or refused. The only reader of `cve_references` is `GetCVEReferences`, which filters by `cve_id` and sorts by `url_canonical`. Neither needs a btree on the URL.
- **Why a digest, not a cap.** Truncating a URL or refusing it at parse time would change what the API returns. With a digest, the uniqueness index still holds for URLs of any length. The merge already deduplicates by canonical URL in Go (`resolve.go`), so the index is a safety net and the `ON CONFLICT` never fires in a merge.
- **Why a wrapper function.** `sha256` takes `bytea`:
  - `text::bytea` parses backslashes as bytea escapes.
  - `convert_to` and `textsend` are STABLE, and PostgreSQL 18.4 refuses STABLE functions in an index expression.
  - `md5(text)` is IMMUTABLE but can fail on a server whose OpenSSL runs in FIPS mode.

  The wrapper calls `convert_to(url, 'UTF8')`. A database's encoding cannot change, so the result is fixed for a given input. The function uses a SQL-standard `RETURN` body for two reasons:
  - golang-migrate splits these files on every `;`, and the `RETURN` body contains none.
  - PostgreSQL resolves the body when the function is created, so `search_path` cannot redirect it later.
- **Dropped `cve_references_url_canonical_idx`.** No query looks references up by URL alone, and this index has the same row limit, so it would have failed next. The index was write cost on every merge.
- **Down migration.** It rebuilds both plain indexes. That fails if a stored canonical URL is over the limit, as its comment says. A semicolon in that comment would have split the statement (DB-16), and was reworded before the first run.
- **Test values.** The long URL's path is 4,096 pseudo-random Cyrillic characters from the existing `randomText` helper. `canonicalizeURL` percent-encodes them, so `url_canonical` is ASCII. At 2,048 characters, the failing index rows were 2,824 bytes, only 120 bytes over the limit, so the length was doubled. Before the fix, rows of 4,984 and 5,448 bytes failed.
- **Other btree indexes over feed text (audit).**
  - The full-ingest worker logs hold 33 row-size errors (SQLSTATE 54000). All 33 are this index, on CVE-2006-4339, from Red Hat. NVD, GHSA and MITRE finished their full ingest with none, and OSV was past 1.2 million of 2.37 million records with none.
  - Already bounded:
    - `cve_cna_affected_check_idx` uses `left(..., 256)` (migration 000059).
    - `package_key` is capped at 2,600 bytes at parse time (`maxPackageKeyBytes`).
    - The watchlist item columns have CHECK limits of 255 and 512 characters.
  - Short identifiers in practice, with no cap in code:
    - `cves.cve_id`
    - `cve_sources.source_id`
    - `severity`
    - the vendor enrichment fields
  - Not bounded in code, and not hit by real data:
    - `cve_affected_packages.package_name`, in `cve_affected_packages_eco_pkg_idx` and `cve_affected_packages_check_idx`
    - `cve_affected_cpes.cpe_normalized`, in `cve_affected_cpes_cve_cpe_uq` and `cve_affected_cpes_cpe_normalized_idx`
    - `cve_cpe_matches.cpe_normalized`, in `cve_cpe_matches_check_idx`

    These are left for Sam to decide. Package registries cap name length, and real CPE strings are a few hundred bytes. A garbage feed record could still fail its merge the same way.
- **Not changed.** One merge error still fails the whole feed job, so a single bad record blocks its feed until the code changes. That is a separate design question.

## Quality checks

- Both new tests failed first with the row-size error on `cve_references_cve_url_uq`, and pass after the change.
- Migration 000060's down and up files were run once against a test database. Down restored `cve_references_cve_url_uq` and `cve_references_url_canonical_idx` and removed the function. Up restored the digest index and the function.
- `go test ./internal/feed/redhat/... ./internal/merge/... -count=1` passes.
- `golangci-lint run` v2.15.0, the CI pin, on `./internal/merge/...` and `./internal/store/...`: 0 issues. The v2.10.1 in `~/go/bin` cannot lint a Go 1.27 module, so this ran through `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0`.
- `go test ./... -count=1 -timeout=600s` passes at 27d3058. The first run failed at setup in `cmd/cvert-ops`, `internal/api` and `web`, because the worktree had no `web/dist`. Those three packages passed after the main checkout's build was copied in.
