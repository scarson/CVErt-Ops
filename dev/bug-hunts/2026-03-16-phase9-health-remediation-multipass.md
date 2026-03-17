# Phase 9 Health Review Remediation — Multipass Bug Hunt

**Date:** 2026-03-16
**Scope:** PR #31 — all 81 changed files across full Go backend (+1769/-703 lines)
**Strategy:** Five focused passes — contract violations, pattern deviations, failure modes, concurrency, error propagation

## Confirmed Bugs

### Bug 1: PostFilter case-sensitivity inconsistency (Medium)

**Files:** `internal/alert/evaluator.go` line 476, `internal/store/dsl_executor.go` lines 249-253

Same finding as exploratory hunt. Alert evaluator pre-lowercases descriptions in SQL (`COALESCE(lower(cves.description_primary), '')`), but DSL executor's `cvePostFilterTarget.PostFilterField` returns raw case. Regex rules behave differently depending on evaluation path.

### Bug 2: Stale file-level comment in `jobs.go` (Low — documentation)

**File:** `internal/store/jobs.go`, lines 3-7

Comment says "All methods use s.q (bound to the raw pool) rather than a transaction helper." But `HasPendingOrRunningJob` (added in this PR at line 122) uses `s.withBypassTx`. Comment is inaccurate.

## Pass Results Summary

1. **Contract violations:** Zero. All store methods return types consistent with interfaces. `AlertRuleStore`, `WatchlistStore`, `JobStore`, `HandlerStore`, `SchedulerStore` implementations verified. Error types consistent (`sql.ErrNoRows` → nil returns).

2. **Pattern deviations:** Zero. All org-scoped methods take `orgID`. Transaction helpers correctly chosen: `withOrgTx` for API paths, `withBypassTx` for auth/pre-context/worker paths, `withOrgRawTx` for squirrel queries. `SetStatementTimeout` uses `%d` format — no injection risk.

3. **Failure modes:** Zero. Transaction rollbacks properly deferred. Worker pool has panic recovery in `safeExecute`. Notification fan-out uses `sync.WaitGroup` (not errgroup). `context.WithoutCancel` correctly used for detached goroutines.

4. **Concurrency:** Zero. Worker pool maps protected by `sync.RWMutex`. Notification semaphores protected by `sync.Mutex`. Eviction check correct (`len(sem) == 0` under lock). `lastClaimAt` uses `atomic.Value`. Scheduler `AddEntries` documented as pre-Start only.

5. **Error propagation:** Zero. `errors.Is(err, sql.ErrNoRows)` used consistently. Error wrapping preserves chain. Context cancellation handled gracefully in worker pool and evaluator. Feed ingestion separates fetch vs merge errors correctly.

## Additional Observation

`toNullRawMessage` is duplicated identically in `merge/pipeline.go` and `store/audit.go`. Both are unexported. Code duplication, not a bug.
