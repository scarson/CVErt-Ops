# Periodic worker tests run on a fake clock

> **Date:** 2026-11-08
> **Scope:** `internal/worker/pool_test.go`; no production code changed

## What was built

| Feature | Files | Description |
|---|---|---|
| Load-independent periodic tests | `internal/worker/pool_test.go` | `TestRegisterPeriodic_ExecutesAtInterval` and `TestRegisterPeriodic_StopsOnContextCancel` run in a `testing/synctest` bubble and assert exact run counts |

## Key implementation decisions

- **Fake clock instead of a longer real-time deadline.** A deadline of several seconds would stop the false failures, but the test would then pass for an interval that is far too long. In a `synctest` bubble the clock advances only when every goroutine is durably blocked, so CPU load cannot change the tick count, and the test can assert exactly 2 runs.
- **Sleep lengths fall between ticks** (125 ms for a 50 ms interval, 70 ms for a 20 ms interval). A sleep ending on a tick would wake the test and the ticker at the same fake instant, and the count could be either value.
- **`StopsOnContextCancel` asserts 3 runs before cancelling.** Without that check, a run with no tick before the cancel compared 0 with 0 and passed without testing anything.
- **`runPeriodic` is unchanged.** It waits for the first tick by design, and reading it showed no bug.
- **The other `time.Sleep` calls in `pool_test.go` are unchanged.** They time a `cancel()` or check an upper bound on concurrency, so a slow host cannot make them fail.

## Gotchas discovered

- **The flake reproduces on demand.** Running the compiled test binary in 20 parallel loops with `GOMAXPROCS=1`, alongside 40 CPU-burning processes on a 20-CPU host, failed 10 of 66 runs before the change with the message from the full-suite failure, and 0 of 39 after it.

## Quality checks

- **`go test ./internal/worker/ -count=20 -run RegisterPeriodic`:** pass
- **`go test ./internal/worker/ -count=1`:** pass, with `TESTCONTAINERS_RYUK_DISABLED=true` after the Testcontainers reaper failed with status "removing" on the first attempt
- **`golangci-lint run ./internal/worker/`:** 0 issues
- **Break-tests of `pool.go`, reverted afterwards:** a doubled ticker interval failed both tests; a task left running after `Start` returned failed `StopsOnContextCancel` with `before=3, after=8`
- **Full suite:** not run locally; CI runs it on the PR from `dev` to `main`, and PRs to `dev` have no CI
