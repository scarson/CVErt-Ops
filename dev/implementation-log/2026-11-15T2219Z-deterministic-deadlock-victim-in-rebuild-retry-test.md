# Deterministic deadlock victim in the rebuild retry test

## What was built

| Feature | Files | Description |
|---|---|---|
| Lock-cycle setup | `internal/merge/reindex_integration_test.go` (`TestRebuildSearchIndex_RetriesBatchAfterDeadlock`) | A third session holds lowID so the rebuild queues on it first; the test session (holding highID, `deadlock_timeout = 60s`) queues on lowID behind the rebuild; then lowID is released. The rebuild takes lowID and starts waiting on highID with the cycle already closed. |
| Wait polling | `internal/merge/reindex_integration_test.go` (`waitForAdvisoryWaiters`) | Waits until n sessions in the test's database are queued for one advisory key, matched by `classid`/`objid` (the key's high and low 32 bits). |

## Key decisions

- **Order the waits instead of tuning timeouts.** Raising only the test session's `deadlock_timeout` would still fail when the cycle closes more than 1s after the rebuild starts waiting. Queueing the rebuild behind a third session makes its wait on highID begin after the cycle exists, so its single check always finds it.
- **No production change.** `RebuildSearchIndex` retries correctly; the defect was the test's setup.

## Gotchas discovered

- Postgres checks a waiting backend for a deadlock once, `deadlock_timeout` after its wait begins, and never again during that wait; the backend whose check finds the cycle is aborted. A 1.2s delay before closing the cycle made the test session the victim every time.
- In the previous setup the two checks were only 18-21 ms apart (measured from `pg_locks.waitstart`, which is the deadlock timer's start). Under full-suite CPU load a backend can run its check later than that, which caused the observed failure (1.94s, too short for the late-close case).
- The test role `cvert_ops_test` is a superuser, so a session can `SET deadlock_timeout`.

## Quality checks

- Break-tests: with a 1.5s sleep before the test session queues, the test passes; with `maxBatchAttempts = 1`, it fails with the rebuild's 40P01. Both reverted.
- `go test ./internal/merge/ -run 'TestRebuildSearchIndex_RetriesBatchAfterDeadlock$' -count=20`: 20 pass, 0 fail.
- `go test ./internal/merge/ -run TestRebuildSearchIndex -count=10 -cpu=1`: pass (10 runs of the retry test).
- `go test ./internal/merge/ -count=3 -parallel=32`: pass.
- `go test ./internal/merge/ -count=1`: pass.
- `golangci-lint run --allow-parallel-runners ./internal/merge/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
