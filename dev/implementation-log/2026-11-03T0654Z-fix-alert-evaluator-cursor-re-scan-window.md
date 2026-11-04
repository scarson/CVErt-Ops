# Fix — Alert Evaluator Cursor Re-scan Window

> **Date:** 2026-11-03
> **Commits:** `95bb14a`..`843acba` on `fix/alert-cursor-clock-skew`
> **Trigger:** `TestEvaluatorEPSS` failed once in a full suite run: `OnlyEPSSRulesEvaluated` and `MixedEPSSAndCVSSRule` found 0 alert events where they expected 1, and passed on rerun.

## What was built

| Component | Location | Description |
|-----------|----------|-------------|
| Re-scan window | `internal/alert/evaluator.go` (`cursorRescanWindow`, `evaluateBatchPath`) | Batch and EPSS runs select candidates from 2 minutes behind the stored cursor |
| Regression tests | `internal/alert/evaluator_test.go` (`TestEvaluatorCursor_RowStampedBeforeCursor`, `TestEvaluatorCursor_RescanDoesNotRedispatch`) | A row stamped 1 s before the cursor is still evaluated on both paths; a re-scanned CVE gets no second event or fan-out |
| Pitfall | `dev/implementation-pitfalls.md` NOTIFY-20 | Evaluator cursor skips rows stamped before it |

## Key implementation decisions

- **Overlap window instead of a database-clock or max-seen cursor** — the cursor is the evaluator's Go clock, `date_epss_updated` is Postgres `now()` (transaction start), and `date_modified_canonical` is the merge worker's Go clock read before its upsert. A database-clock cursor fixes only the EPSS path's clock mismatch; a max-seen cursor fixes skew on both paths. Neither covers a writer that commits after the evaluator's scan with a timestamp before the cursor. The overlap covers both, and re-evaluation is idempotent (`alert_events` `ON CONFLICT DO NOTHING`, fan-out only on insert).
- **Two minutes** — skew and commit lag are normally well under a second; two minutes is one batch scheduling interval, so a batch run's candidate set at most doubles. A larger candidate set makes the 5,000-row candidate cap easier to reach.

## Gotchas discovered

- **Skew was not observable after the fact** — after a Docker Desktop restart the Postgres container clock read about 130 ms ahead of the host (±120 ms), so the lag at failure time could not be measured. The deterministic test reproduces the mechanism instead.
- **Same pattern elsewhere** — the digest worker sets `last_run_at` from a Go timestamp taken after its query (`internal/notify/digest.go`), and partial (cap-exceeded) rule runs still advance the alert cursor. Both are tracked as separate tasks.

## Quality checks

- **Red:** with the pre-fix `evaluator.go`, both subtests of `TestEvaluatorCursor_RowStampedBeforeCursor` found 0 events and `TestEvaluatorCursor_RescanDoesNotRedispatch` saw one batch run instead of two.
- **Tests:** `go test ./internal/alert/ -count=1` passes (40 top-level tests, 537 s).
- **Lint:** `go vet` and `golangci-lint run ./internal/alert/...` clean.
