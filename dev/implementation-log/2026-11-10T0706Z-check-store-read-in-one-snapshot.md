# Check store read in one snapshot

## What was built

- Task 3.9 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `df55220`.
- `internal/store/store.go`: `withOrgRawTx` now calls `withOrgRawTxOptions(ctx, orgID, opts, fn)` with `nil`. `withOrgSnapshotTx` calls it with `sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}` (design section 5: one snapshot, so a merge committing between two statements cannot mix old NVD rows with new CNA rows).
- `internal/store/check.go`: `ReadCheckCandidates(ctx, orgID, keys)` returns `check.Candidates`, enrichment keyed by `cve_id`, and the `feed_sync_state` rows of `ghsa`, `nvd` and `osv`. It calls `readCheckCandidates` with `defaultCheckLimits` (50,000 rows per key, 200,000 rows and 128 MiB per request) and no callback.
- The five lookups are the plan's statements: each joins `unnest(...) WITH ORDINALITY` through `CROSS JOIN LATERAL (... LIMIT KeyRows+1)` and returns the 1-based key position, converted to the 0-based slot. A key that receives more than `KeyRows` rows keeps `KeyRows` and sets `Overflow`. Every key slot is present; a lookup whose key slice is empty is not run.
- Enrichment reads `cves` for every advisory ID kept and every ID `check.CVEIDsFor` derives from them. It is not run when no advisory was kept.
- `ErrCandidateLimit`, wrapped with the limit passed, is returned when rows read over all statements pass `RequestRows`, or bytes pass `RequestBytes`.
- `internal/store/export_test.go` exposes `readCheckCandidates` (as `ReadCheckCandidatesWith`), `checkLimits`, the default limits, and the two index expression builders to the `store_test` package.
- `internal/store/check_index_test.go`: pin tests for the CPE index (`cpe_normalized COLLATE "C"`) and the CNA index (`left(lower(vendor), 256) COLLATE "C"`, same for `product`) against migration 000059, beside the existing package index pin. The statements build these predicates from `cpeIndexExpr` and `cnaNameIndexExpr`, which the tests compare with the migration text.

## Decisions and gotchas

- NULL text columns read as `""` through `COALESCE` in SQL, including `cves.status`. CNA vendor and product are returned as stored (not lower-cased), because `Evaluate` compares nearby rows with name rows byte for byte.
- The CNA package key statement selects `cve_id`, `versions` and status, as the plan writes it, so those `CNARow`s have empty `Vendor` and `Product`. `Evaluate` does not read them for package key rows.
- Request bytes count the length of every string field read plus the raw `versions` JSON as Postgres returns it. A row past a key's limit still counts towards the request totals, because it was read. Its CVE ID is not added to the enrichment set: an overflowing key makes its item `too_many_candidates` with no advisories listed, so nothing needs it.
- The feed list `ghsa`, `nvd`, `osv` is repeated in the store, because `internal/check` keeps its feed names unexported.
- `testutil.SeedCorpus` calls `t.Setenv`, so the test that uses it cannot call `t.Parallel()`.
- Tests seed CVE data with `merge.Ingest` of targeted `CanonicalPatch` values and `SeedCorpus`, never raw SQL, and read as the application role (`AppStore`).

## Quality checks

- The tests were written first and failed to build (`readCheckCandidates`, `checkLimits` and the index expression builders undefined).
- Break tests, each run and then reverted: default isolation in `withOrgSnapshotTx` fails `TestReadCheckCandidates_OneSnapshot` (the later statements saw the CPE row, the severity and the cursor committed after the first statement); `>` instead of `>=` at the key limit fails `TestReadCheckCandidates_KeyLimit`; 255 instead of 256 in `cnaNameIndexExpr` fails `TestCheckCNAIndexMatchesQuery` and `TestReadCheckCandidates_CNANames` (the 259-character exact name).
- `go test ./internal/store/ -run 'ReadCheck|CheckCPEIndex|CheckCNAIndex|CheckPackageIndex' -count=1 -v`: pass, 15 tests.
- `go test ./internal/store/ -run 'Org|ReadCheck|CheckPackageIndex|Check' -count=1 -v`: pass, 108 tests and subtests, none skipped.
- `golangci-lint run ./internal/store/...`: 0 issues.
