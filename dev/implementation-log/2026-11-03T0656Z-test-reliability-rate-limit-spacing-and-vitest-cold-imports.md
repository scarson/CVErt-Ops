# Test Reliability — Rate-Limit Spacing and Vitest Cold Imports

**Date:** 2026-11-03

## What was built

| Part | Files | Description |
|---|---|---|
| Rate-limit test | `internal/feed/generic/adapter_test.go` | `TestAdapter_RateLimiting` delays the first request 150ms in the transport and asserts the second request arrives at least 499ms after the first `Fetch` began |
| Vitest component imports | 24 files under `web/src/**/__tests__/` | Components and views are imported statically at the top of the file instead of by `await import()` inside each test |
| Router guard tests | `web/src/router/__tests__/guards.test.ts` | A top-level `await` loads every lazily imported route view while the file is collected |

## Key implementation decisions

- **The limiter was correct; the assertion measured the wrong interval.** With rate 2 and burst 1, `rate.Limiter` guarantees that the second `Wait` returns 500ms after the first `Wait` began. The test compared arrival times at the server, and that gap shrinks by however much longer the first request took to arrive, for example the first TCP dial on a loaded host. On Windows it measured 397.5ms. The 1ms allowance covers `durationFromTokens` truncating its float result to whole nanoseconds.
- **Cold import cost belongs in collection, not in a test.** Vitest applies `testTimeout` to each test but not to collecting a file, so a static import or a top-level `await` keeps the per-file cold transform and import out of every test's budget. The global timeout was left at the 5s default.

## Gotchas discovered

- **A timed-out vitest test keeps running.** Vitest cannot cancel the test's async body. In `WatchlistDetailView.test.ts` the timed-out loading test later finished its import, mounted the view and consumed the next test's `mockResolvedValueOnce`. Its `mockImplementation(() => new Promise(() => {}))` also stayed in place, because `vi.clearAllMocks()` clears calls, not implementations. The 404 test's request then hung and it showed "Loading watchlist...".
- **Every slow vitest test was the first in its file** (24 of 24 over 500ms; 1.4–3.8s on an idle machine), so the timeouts moved between files from run to run.

## Quality checks

- **Rate-limit test:** a 150ms first-request delay reproduced the failure (347.9ms) with the old assertion. The fixed test passes 20 of 20 runs and `-race`, and fails (152ms) with the limiter set 1000x faster. golangci-lint: 0 issues.
- **Vitest:** at `--testTimeout=1000`, the old tests reproduced the WatchlistDetailView cascade and the guards timeout, and the fixed tests pass. On an idle machine, summed test time fell from 83.5s to 11.1s and the slowest test from 3835ms to 276ms. With three full suites run at once: the old tests failed 35 tests per run (slowest 12.5s); the fixed tests passed all 430 in each run (slowest 648ms). `type-check` and `lint` are clean.
- **Full Go suite:** not run; the Docker engine returned HTTP 500 for the whole session.
