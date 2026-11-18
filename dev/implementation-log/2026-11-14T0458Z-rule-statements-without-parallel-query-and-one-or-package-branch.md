# Rule statements run without parallel query, and an "or" rule's package names match in one branch

## What was built

| Feature | Files | Description |
|---|---|---|
| Parallel query off for rule statements | `internal/alert/evaluator.go` | `candidateTxSettings` lists `SET LOCAL jit = off` and `SET LOCAL max_parallel_workers_per_gather = 0`; `prepareCandidateTx` runs them in order in the transaction of every `queryCandidates` call (realtime, batch, EPSS, activation, dry-run). Saved searches (`internal/store/dsl_executor.go`) are unchanged. |
| One package branch under "or" | `internal/alert/dsl/sets.go`, `compiler.go`, `types.go` | `Compile` calls `mergeOrPackageNames` first: under `or`, every `affected.package` condition with `eq` or `in` is replaced by one `in` condition holding all their values, in rule order, where the first of them stood. `packageMatch` then folds and de-duplicates the names per arm (PyPI arm, lower-case arm) as for any `in` list, so the rule binds the candidate array and two name arrays once. Substring package conditions and ecosystem sets keep their own branches. Under `and` nothing changes. The rule's conditions slice is never modified, and the compiled rule's closures stay pure. |
| Harness | `internal/alert/kept_ingest_measure_test.go` | Every evaluator-shaped measurement applies all of `candidateTxSettings`; the saved-search row M4 runs without them. The merged-forms test compares the server defaults with `candidateTxSettings`. |
| Tests | `internal/alert/dsl/sets_test.go`, `internal/alert/candidate_tx_test.go`, `internal/alert/product_match_test.go` | Unit tests pin the exact SQL and arrays of `or` over package eq `a`, package in `[B_c, d, A]`, product `nodejs:node.js` and severity (one package branch with `[a, b-c, d]` and `[a, b_c, d]`, then the product branches, severity OR-ed beside the set); 1 and 50 one-value package eq conditions under `or` give the same SQL and 2 arguments without candidates, 3 with; substring and ecosystem branches stay separate; `and` keeps one set per package condition. The transaction test checks `jit` off and `max_parallel_workers_per_gather` 0 inside the transaction and both defaults restored after it on the same connection. The every-path test adds the package match corpus (built through `merge.Ingest`) and an `or` rule of `Foo_Bar`, `lodash` and `in [jspdf]`, which must equal the union of its conditions alone through `store.ExecuteDSLQuery` and an activation scan, match the PyPI `foo-bar` row and both lodash rows, and not the npm `foo-bar` row. |

## Key decisions

- **Sam's third remedy for the MATCH-2 Phase 4 measurement gate** (`dev/plans/2026-11-13-product-match-rules-measurements.md`, "After the remedy"): the limit rule under `or` spent about 20 ms of a 26.4 ms realtime run in a parallel plan for one CVE, 0.8 s of a 3.2 s 5,000-ID batch planning the candidate array repeated in 50 package branches, and activation hit the 64 MB shared-memory limit through parallel hashes.
- Merging is exact: under `or` package conditions are uncorrelated (design section 4.2), and a CVE has a row matching one of several names exactly when it has a row matching one name of their union.
- The merge rewrites the rule before compilation instead of adding a case to `CompiledRule.Where`, so a single package condition compiles byte for byte as before and no golden entry changed (`testdata/where.golden` holds no `or` rule with two or more package eq/in conditions).
- Pitfall DB-27 records both changes.

## Quality checks

- `go test ./internal/alert/dsl/... -count=1`: pass (201 tests, 213 with subtests). The new `or` tests failed first on one package branch per condition.
- `go test ./internal/alert/... -count=1`: pass (281 tests, 393 with subtests, both packages). The transaction test failed first on `max_parallel_workers_per_gather` = 2.
- `go test ./internal/store/... -count=1 -run DSL`: pass (22). `go test ./internal/api/... -count=1 -run 'AlertRule|SavedSearch|AI'`: pass (97).
- `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...` and with `--build-tags keptingest ./internal/alert/`: 0 issues.
- Not done: the new settings and the merged package branch have not been measured on the kept full ingest; the harness needs a rerun.
