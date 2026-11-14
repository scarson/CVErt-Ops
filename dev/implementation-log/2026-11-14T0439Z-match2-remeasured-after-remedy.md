# MATCH-2: re-measured after the merged set form, JIT off and array matching

## What was built

| Feature | Files | Description |
|---|---|---|
| Re-measurement | `dev/plans/2026-11-13-product-match-rules-measurements.md` | Every Phase 4 row after `7ad8080` (one `IN` per `or` rule, JIT off) and `fe0e32f` (candidate product sets against bound arrays), plus the sweep after the merge. |
| Harness | `internal/alert/kept_ingest_measure_test.go` | Evaluator-shaped rows run with `candidateJITOff`, as `queryCandidates` does; adds a serial limit-rule test and a plan dump used to read failing rows. Build tag `keptingest`, read-only. |

## Key decisions

- The gate still fails for the limit rule (M5a realtime 26.4 ms, M5b dry-run 11.0 s, M5c batch 3.2 s, M8 about 22 minutes and a shared-memory error). Per Sam's instruction the numbers go to him before any further remedy is chosen.
- Single-product batch rows still pass but rose from about 30 ms to up to 505 ms: with 5,000 candidate IDs the planner chooses parallel sequential scans of `cve_cpe_matches` and `cve_cna_affected` for the array form.

## Quality checks

- `go vet -tags keptingest ./internal/alert/`: clean.
