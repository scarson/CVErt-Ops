# Run saved and AI search under the rule query settings

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared settings | `internal/alert/dsl/query_settings.go` | `RuleQuerySettings` (`SET LOCAL jit = off`, `SET LOCAL max_parallel_workers_per_gather = 0`) and `PrepareRuleQueryTx`, which applies them to a transaction. Moved from `internal/alert/evaluator.go` (`candidateTxSettings`, `prepareCandidateTx`), because `internal/store` cannot import `internal/alert`; both packages import `internal/alert/dsl`. |
| Evaluator | `internal/alert/evaluator.go` | `queryCandidates` calls `dsl.PrepareRuleQueryTx`. Behaviour unchanged. |
| Saved and AI search | `internal/store/dsl_executor.go` | `ExecuteDSLQuery` runs every rule in a read-only transaction under `RuleQuerySettings` (`queryDSLRows`). A rule with watchlists also gets `SET LOCAL app.bypass_rls = 'on'`, as before. Rules without watchlists ran on the pool with the server defaults (JIT and parallel query on). |
| Test | `internal/store/dsl_executor_settings_test.go` | `TestExecuteDSLQuery_RunsUnderRuleQuerySettings` |

MATCH-2's measurements on the 2.6 M-CVE ingest (`dev/plans/2026-11-13-product-match-rules-measurements.md`) found JIT adding about 4 s to a 50-product dry run and parallel hashes exhausting Docker's 64 MB `/dev/shm`. The evaluator already ran rule statements without them; a large `or` rule run as a saved search did not.

## Key decisions

- The test sees the settings from inside the statement that `ExecuteDSLQuery` runs: each check appends a join `(SELECT 1) AS settings_check ON <condition>` to the compiled rule's exported `Joins`, so the seeded CVE comes back only when the condition holds. It checks read-only, JIT off, parallel query off, and RLS bypass on with watchlists and off without them, for rules with and without `HasWatchlist`. It runs as the app role on a one-connection pool, then checks with `SHOW` that the connection is back at the server defaults (the settings are `SET LOCAL`).
- A page now costs BEGIN, two `SET LOCAL` statements and COMMIT beyond the query: a few round trips against statements that can take seconds.
- `TestPrepareCandidateTx_TurnsJITAndParallelQueryOffForTheTransaction` (`internal/alert/candidate_tx_test.go`) is renamed `TestPrepareRuleQueryTx_...` and calls `dsl.PrepareRuleQueryTx`; it stays in package `alert`, which can use `testutil`. The kept-ingest measurement harness (build tag `keptingest`) uses `dsl.RuleQuerySettings`.
- `dev/implementation-pitfalls.md` (product-match planning cost entry) names `dsl.RuleQuerySettings` and the saved-search path.

## Pitfall check

`/pitfall-check` on `internal/store/dsl_executor.go`, `internal/alert/dsl/query_settings.go`, `internal/alert/evaluator.go` and the new test: no issues. The settings are `SET LOCAL` and end with the transaction (ARCH-6); the transaction is read-only and sets the RLS bypass only for watchlist rules, as before; the rejected/withdrawn filter and the keyset cursor are unchanged.

## Quality checks

- `TestExecuteDSLQuery_RunsUnderRuleQuerySettings` failed first (read only, JIT and parallel query checks without watchlists; JIT and parallel query checks with them), then passed.
- `go test ./internal/store/ -run TestExecuteDSLQuery -count=1`, `go test ./internal/alert/... -count=1`: pass.
- `go test ./internal/api/ -count=1 -run 'SavedSearch|AISearch|NLSearch|AI'` (39 tests): pass.
- `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0 on `./internal/store/... ./internal/alert/...`: 0 issues.
