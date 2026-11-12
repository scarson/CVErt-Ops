# Check endpoint phase-end review fixes, round 2

## What was built

Eight commits from the second round of Phase 3 phase-end reviews of `POST /api/v1/orgs/{org_id}/check`, the version check endpoint of `dev/plans/2026-11-09-version-check-endpoint-plan.md`. Test first in each, except where noted.

- `b4a1e86` fix(check): each row of the CNA name table (design section 4.5) now lists the CPE `vendor:product` keys that share it (`cnaMapping.CPEs`). `cnaTable` in `internal/check/names.go` is a list of rows, and `cnaNames` indexes it by each listed CPE. A CPE item reads `cve_cpe_matches` under every listed key, with its own part (`itemKeys.cpes`); with no table row it reads its own prefix only. Before this, `cpe:2.3:a:f5:nginx` 1.13.0 never read older nginx CVEs, whose NVD rows are under `nginx:nginx` only, and could answer `not_affected`; the same held between `microsoft:.net` and `microsoft:.net_core`. The nginx row also gains the CNA name `nginx` / `nginx` (CVE-2017-7529, design section 2).
- `f03fc7c` fix(check): when a CPE's vendor or product holds an unescaped `_`, its own CNA name is looked up a second time with `_` kept (`ownNames`), and for a CPE with no table row a second nearby-name key keeps `_` in vendor and fragment (`nearbyNames`). An item may now use several nearby-name keys (`itemKeys.near`). Before this, a CNA product stored as `foo_bar` matched neither `foo bar` nor the fragment.
- `327a6f6` fix(check): `parseCPE` drops a backslash before `.`, `-` or `_` in vendor and product (`dropRedundantEscapes` in `internal/check/input.go`). These never need escaping in a CPE 2.3 formatted string and NVD writes them bare, so `node\.js` now reads NVD's `node.js` rows and the `nodejs:node.js` table row. Other escapes (`\:`, `\!`, `\\`) are kept.
- `da47312` fix(api): `writeCheckFailure` answers PostgreSQL error `57014` (query_canceled, which `statement_timeout` reports) with the same 503 as the check time limit, without an error log. `DB_STATEMENT_TIMEOUT_MS` defaults to 14 s, shorter than the 30 s `checkTimeout`, so a slow lookup could end with the context still live and was answered 500.
- `48b48c4` test(api): `blockingWriter` in `internal/api/check_test.go` records `SetWriteDeadline` calls and any `Write` made before one. `TestCheckAPI_SlotHeldOnlyWhileChecking` asserts one deadline, `checkWriteTimeout` after the handler ran, set before the first `Write`.
- `7b670e6` fix(store): `readKeyRows` defers `cancel()` after `rows.Close()`, so the statement's context is cancelled before the deferred Close on every return: scan, decode and key-position errors as well as the request limit. The explicit `cancel()` before returning `ErrCandidateLimit` is gone, since the deferred one now runs first. The five lookups `LEFT JOIN cves`, so a row with no `cves` row is returned and counted rather than dropped after the per-key `LIMIT` inside the LATERAL.
- `393ef61` test(store): `TestWithOrgSnapshotTx_Mode` reads `SHOW transaction_read_only` and `SHOW transaction_isolation` inside `withOrgSnapshotTx` (exported through `export_test.go`) and expects `on` and `repeatable read`.
- `a4fa730` refactor(check): `check.FeedNames()` returns the feeds `FeedStatuses` reports on, sorted, from the same table; `internal/store/check.go` reads `feed_sync_state` for it instead of its own `checkFeeds` copy.

## Decisions and gotchas

- Nearby names for a CPE spelling (fix A): the nearby-name check still excludes CVEs with a `cve_cpe_matches` row under the item's own CPE vendor only, not under the other spellings' vendors. A `f5:nginx` item whose CVE has NVD rows only under `nginx:` and a CNA row `F5` / `NGINX Plus` answers `cna_name_uncertain` for it. That is cannot evaluate, never a wrong `not_affected`, so it was left.
- The `_`-kept nearby key (fix B) applies only to a CPE with no table row: a table row's vendor and fragment come from the table, not from the CPE.
- Fix C makes `ProductRef` hold no `\.`, `\-` or `\_` when it comes from `parseCPE`, so `\_` and bare `_` now give the same keys (both read `_` as a space in the first CNA name and keep it in the second). `NamesFor` tests that build a `ProductRef` with `\.net` directly are unchanged.
- The nearby-name SQL compares the fragment with `strpos`, not `LIKE`, so a `_` in a fragment is a literal character.
- Fix D also turns any other 57014 with a live context (such as `pg_cancel_backend` from an operator) into the 503; the response text still names the 30 s limit.
- Fix F, scan-error test: no lookup can fail to scan its own rows, so `ReadKeyRowsFailingScan` in `export_test.go` runs `SELECT g FROM generate_series(1, 100000)` through `readKeyRows` with a scan that fails on the first row. Before the fix the pgx tracer saw `SELECT 100000` with no error; after it the statement ends with an error and the one-connection pool answers the next read. The traced pool setup moved into a `tracedStore` helper shared with `TestReadCheckCandidates_RequestLimitStopsStatement`.
- Fix F, `LEFT JOIN`: no test. `cve_affected_packages` has no foreign key to `cves` (`cve_cpe_matches` and `cve_cna_affected` have deferred ones), but the merge pipeline always writes the `cves` row, so a store test cannot build an orphaned row without a raw insert, which `dev/testing-pitfalls.md` section 7 rules out. It rests on review.
- Break tests: the write-deadline assertion failed with the `SetWriteDeadline` call removed; the snapshot-mode test failed with `ReadOnly: false` and with `sql.LevelReadCommitted`. Each was restored with `git checkout --`.
- A Bash heredoc dropped one backslash from `'\\'` in `cnaText` while `names.go` was rewritten for fix B (the long-commands papercut); it was caught by the build and fixed with the Edit tool before the commit.
- To keep one fix per commit, fix C's `TestKeysForRedundantEscapes` was held out of `keys_test.go` while fix B was committed, then restored.

## Quality checks

- `go test ./internal/check/ -count=1 -v`: pass, 80 tests (605 with subtests).
- `go test ./internal/api/ -run 'Check|OpenAPI' -count=1 -v`: pass, 32 tests (150 with subtests); also passed after fix A, after fix B and after fix C. No expectation in `internal/api/check_integration_test.go` changed.
- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1 -v`: pass, 21 tests.
- `golangci-lint run ./internal/check/... ./internal/store/... ./internal/api/...`: 0 issues.
- Full suite not run.
