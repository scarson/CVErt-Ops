# Check endpoint: the CPE lookup leaves rows below the version unread

## What was built

Commit `08b6595` (feat(check)), on top of `e47153e` in PR #218's branch. Sam asked for it on 2026-11-10 after the Phase 4 provisional measurement in `dev/plans/2026-11-09-version-check-endpoint-plan.md`: `o:linux:linux_kernel` has 82,061 vulnerable `cve_cpe_matches` rows on the partial ingest, over the 50,000-row key limit, so every kernel item answered `too_many_candidates`. Design sections 4.2 and 9 of `dev/plans/2026-11-08-version-check-endpoint-design.md` are amended with the rule and the measurements.

- `internal/version/below.go`: `ProductRangeBelow(version, range)` reports a range lying wholly below a version: one upper bound, following `Introduced`, decided below the version by `CheckProduct`'s leading-number rule, between bounds holding none of `% * ? \ : !`. `ProductRangeBelowSQL`, `LeadingSQL` and `DottedSQL` build the same rule as a SQL expression.
- `internal/check`: `CPEKey.Floor` is the first two components of a dotted-number item version (`versionFloor`). `CPERow.Below` marks a row that stands for a CVE's left-out rows. `CPERowBelow` is the rule on a stored row. `EvaluateCPERows` takes the count of left-out rows, which are compared rows answering Not affected; `evaluateAdvisory` adds them to the range limit and to "has NVD rows".
- `internal/store/check.go`: the CPE statement. A key with no floor reads under the `LIMIT` as before. A key with a floor reads its product once into a materialised CTE, marks the rows the rule reports, and returns the unmarked rows and one count row per CVE.
- `internal/store/store.go`: `withOrgSnapshotTx` runs `SET LOCAL jit = off`.

## Decisions and gotchas

- **Only rows below the version are left out.** The first idea, keeping rows whose leading numbers allow the version, also drops rows above it. `PickFix` checks each fix candidate against every range of the advisory, and a range above the version can reject one (`[2.0, 3.0)` rejects the `2.0` of `[1.0, 2.0)`). A range below the version answers Not affected for every version at or above it, so it can never reject a candidate.
- **CNA fix candidates.** A CNA candidate is above the version in its entry's own order, not in dotted-number order. `TestCNAOrdersNeverPlaceADottedNumberBelowNumericOrder` checks, for `semver`, `python`, `maven`, `rpm` and `custom`, that no order places a dotted number below one that `NumericOrder` places above it. If a version type is added to `orderFor`, that test must cover it.
- **A count row per CVE, not a dropped CVE.** A CVE whose rows are all left out must stay NVD-analysed (design 4.4 step 4), counted in `counts`, counted as retracted by its status, and its rows must count towards its 1,000-range limit. The count row carries all of that. It counts as one row towards the key, item and request limits.
- **The floor is two components, not the whole version.** Each distinct product and floor reads the whole product (about 2.8 µs a row). Two components keep versions of one release line on one read. A statement that reads the product once for all of its versions was built and measured: one version cost 340 to 390 ms against 238 ms, and each further version 120 to 145 ms, so it was not kept.
- **SQL NULL.** The rows to keep are selected with `IS TRUE` on the rule, so a NULL from any part of the rule keeps the row. The first draft used `NOT (rule)`, which would have lost such a row from both halves.
- **SQL casts.** Leading numbers are cast to `numeric[]`, which takes at most 131,072 digits. The cast sits inside a `CASE` that first limits the bound to 256 bytes.
- **Escapes.** `splitCPE` skips the byte after a backslash. The SQL replaces each escaped character with a lone backslash before splitting on `:`, so the component count agrees with Go and a component that held an escape is never read as a version.
- **Cost of the SQL rule.** Written inline, the rule was evaluated about 100 times per row (4.0 s for the kernel). Computing each bound once in `LATERAL (... OFFSET 0)` items, and reading the product once in place of twice, brought it to 0.24 s.
- **Status lookup.** With `LEFT JOIN cves` the planner chose a hash join over all of `cves` (about 80 ms) because it cannot estimate the lateral's rows; a scalar subquery per returned row avoids it.
- **JIT.** The statement's estimated cost passes PostgreSQL's JIT thresholds: 30 to 70 ms for one key, 0.96 to 1.24 s for four or five keys, with nothing saved. Hence `SET LOCAL jit = off` in the snapshot.
- **gofmt and `''`.** gofmt rewrites `''` in a doc comment to a typographic quote. Comments that describe SQL say "empty".
- **Worktree base.** The agent worktree was created at `main` (`74ab722`), not at `e47153e`. The branch had no commits and a clean tree, so it was moved to `e47153e` before work began.

## Measured (copy of the partial ingest, `cvert_phase4`, PostgreSQL 18.4, JIT off, custom / generic plan)

| Key (floor) | Before: rows, time | After: stored rows + CVE counts, time |
|---|---|---|
| Kernel `6.12.0` (`6.12`) | 50,001 of 82,061 (limit), 81 / 24 ms | 14 + 2,050, 238 / 231 ms |
| Kernel `2.6.32` (`2.6`) | 50,001 (limit), 76 / 24 ms | 50,001 (limit) + 218, 327 / 319 ms |
| Kernel, no floor | 50,001 (limit), 77 / 25 ms | 50,001 (limit), 86 / 85 ms |
| Firefox `130.0` | 35,051, 61 / 21 ms | 37 + 1,418, 96 / 99 ms |
| Chrome `120.0` | 31,425, 48 / 17 ms | 11 + 1,535, 100 / 95 ms |
| PHP `8.3` | 16,090, 33 / 9 ms | 4 + 592, 49 / 46 ms |
| OpenSSL `3.0` | 4,299, 7 / 3 ms | 82 + 165, 13 / 13 ms |

The endpoint was not re-timed end to end. Package and CNA rows were assessed and not changed; see the plan's Phase 4 notes ("Rows below the version").

## Quality checks

- `go test ./internal/version/ ./internal/check/ -count=1`: pass. New: `TestProductRangeBelow` (45 cases), `TestProductRangeBelow_NeverHidesAnAnswer`, `TestProductRangeBelow_FindsWhatCheckProductClears`, `TestCPERowBelow` (23 cases), `TestKeysForCPEFloor`, `TestVersionFloorIsAtOrBelowTheVersion`, `TestEvaluateRowsBelow` (5 cases), `TestEvaluateLeavingOutRowsBelowChangesNoAnswer` (1,028 CVEs, 15 versions), `TestCNAOrdersNeverPlaceADottedNumberBelowNumericOrder`.
- `go test ./internal/store/ -run 'ReadCheck|Check|Snapshot' -count=1`: pass. New: `TestReadCheckCandidates_CPERowsBelow` (5,085 stored rows, 12 floors, SQL against the Go rule), `TestReadCheckCandidates_CPERowsBelowChangeNoAnswer`, `TestReadCheckCandidates_CPERowsBelowKeyLimit`; `TestWithOrgSnapshotTx_Mode` also pins `jit = off`.
- `go test ./internal/api/ -run Check -count=1`: pass.
- Each new test failed before its change: the version and check tests did not build, the three store tests failed on row counts, and the JIT assertion read `on`.
- `golangci-lint run ./internal/check/... ./internal/store/... ./internal/version/...`: 0 issues.
- The full suite was not run; the controller runs it.
