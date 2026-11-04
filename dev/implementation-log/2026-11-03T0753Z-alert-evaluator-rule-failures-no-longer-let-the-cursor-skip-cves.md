# Alert Evaluator — Rule Failures No Longer Let the Cursor Skip CVEs

> **Date:** 2026-11-03
> **Branch:** `fix/alert-rule-error-cursor`
> **Source:** follow-up to the candidate cap fix: a rule that errors or fails to compile also let the batch/EPSS cursor move past CVEs it never evaluated

## What was built

| Part | Files | Description |
|---|---|---|
| Uncompilable rules | `internal/alert/evaluator.go` | `failUncompilableRule` logs the compile failure and moves the rule from `active` to `error` in the realtime, batch and EPSS paths, matching the activation scan |
| Held cursor | `internal/alert/evaluator.go` | `evaluateBatchPath` keeps the previous cursor when any rule errors or returns partial; `evalCursor.HeldRuns` in `cursor_json` counts consecutive held runs, capped by `batchMaxHeldRuns` (30) and `epssMaxHeldRuns` (3) |
| Spec | `PLAN.md` §10.3 | Cursor advancement rule for the batched and EPSS-specific jobs |

## Key implementation decisions

- **Hold the global cursor, not a per-rule cursor**: no migration, and re-evaluating the held window is idempotent for healthy rules. A per-rule cursor would isolate the extra work but needs a schema change, activation and re-activation changes, and still needs a cap for a rule that fails on every run.
- **Cap by consecutive held runs, not cursor age**: after the worker has been down for days, the cursor is already old; an age cap would advance past the first failure without any retry.
- **A held run still sets `last_success_at`**: the scheduler (`internal/ingest/scheduler.go`) enqueues the next run when `last_success_at + Interval` has passed. Leaving it unset would re-enqueue the daily EPSS job on every scheduler tick and use up its held runs within minutes.
- **No automatic disable after repeated failures**: a short database outage would fail every rule, and re-enabling runs activation with delivery suppressed, so missed CVEs would never notify.

## Quality checks

- **golangci-lint:** 0 issues on `internal/alert`
- **New tests:** `TestEvaluateBatch_RuleErrorDoesNotSkipCVEs`, `TestEvaluateBatch_PersistentRuleErrorAdvancesCursorAfterCap`, `TestEvaluator_UncompilableRuleSetToError` (batch and realtime subtests). The first two failed before the fix; the realtime subtest was written together with the fix.
- **Tests run locally:** only the new tests, because of Docker contention on the dev host; CI runs the full `internal/alert` package.
