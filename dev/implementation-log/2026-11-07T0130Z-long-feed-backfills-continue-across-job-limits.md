# Long feed backfills continue across job limits

## What was built

- The feed handler in `internal/ingest/handler.go` ends a run between pages once less than `pageReserve` (3 minutes) of job time remains and pages are left. The run writes `feed_fetch_log.status = 'partial'`, saves the cursor, clears failure tracking and leaves `LastSuccessAt` unchanged, and the job succeeds.
- A deadline that interrupts a page after at least one page completed gets the same outcome. The next job merges that page again. A deadline before any page completes is still a failure.
- `worker.OutcomeContext` gives outcome writes a context detached from the job context and bounded by `recordOutcomeTimeout`. The pool, the feed handler and the EPSS handler all use it, so a failure at the deadline now reaches `feed_sync_state` and `feed_fetch_log`.
- `staleThreshold` is now `maxJobDuration + 2 minutes`.
- `epss.Adapter.Apply` returns an error when the context has ended, instead of skipping every remaining row.
- Both feed views show a `partial` log with a neutral badge through `web/src/lib/feedLogStatus.ts`.

## Key decisions

- Continuation goes through the scheduler, not a new queue operation. Because a partial run leaves `LastSuccessAt` alone, the feed stays due, so the next one-minute tick enqueues a new job with fresh attempts. This needs no migration and no new job state, and a paused feed stops at the next tick. The handler cannot enqueue the job itself, because its own running job holds the `lock_key` and `EnqueueJob` would do nothing.
- Failure tracking is cleared on a partial run because `FailJob` retries ignore `BackoffUntil`. A retry that progresses while a backoff is still in the future would otherwise leave the scheduler skipping the feed.
- Only a completed page counts as progress. If a time-limited run with no completed page were also recorded as partial, a page too large for one job would repeat forever and report no failure.
- `pageReserve` is a fixed value sized from the real backfill: about 8,000 CVEs in 10 minutes is about 13 per second, so a 2,000-CVE NVD page takes about 150 seconds. A slower system falls through to the deadline path, which only costs repeating one page.
- The empty-page stop in the handler is unchanged and is checked before the time limit, so a run that has reached its end records success even near the deadline.

## Gotchas

- `maxJobDuration` and `staleThreshold` were equal. A handler that runs to the deadline is still writing its outcome after it, so a recovery tick in that window set the job back to `pending` while it was finishing. Another worker could then claim it, and the first worker's `CompleteJob` or `FailJob` would overwrite the status of the running job, because those queries match on `id` alone.
- Detaching the EPSS outcome writes alone would have made EPSS worse. `Apply` logged each failed row and returned a next cursor, so a run at the deadline looked successful, and only the expired context on the success write kept that false success out of the database. With the write detached, the same-day cursor check would have skipped the unapplied rows until the next day's file. That is why the adapter changed too.
- `Fetch` on NVD can spend minutes walking empty windows without returning, and the cursor saves only when it returns. A walk longer than one job would count as a failure with no progress. The 2026-11-06 walk took about 6.5 minutes, so it fits today.

## Known limits

- A manual trigger of a feed that succeeded recently, if it then stops at the time limit, waits until the feed's interval has passed since that success. It still continues without action. Scheduled runs are unaffected, since they start only when the interval has already passed.
- MITRE and OSV return their whole archive as one page, so a first backfill larger than one job cannot complete a page. The handler now records that as a failure with backoff, but it does not finish. EPSS applies its whole file in one call and has the same limit. These need their own design.

## Quality checks

- New tests failed before the change, with the incident's `begin bypass tx: context deadline exceeded` error on the handler paths, and pass after it.
- `go test ./internal/ingest/ ./internal/worker/ ./internal/feed/epss/ -count=1` passes, using `TESTCONTAINERS_RYUK_DISABLED=true` because of the known reaper `removing` failure on this host.
- `golangci-lint run` is clean on the changed packages. The web feed view and helper tests, `npm run type-check` and eslint on the changed files pass.
- Not run against the live NVD API. The behaviour is covered with mock adapters and a real database, including a test that the scheduler enqueues the next job after a partial run.
