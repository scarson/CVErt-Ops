# Failed EPSS run can succeed the same day

## What was built

- The EPSS adapter's rate limiter now allows one download per minute (`minDownloadInterval`, burst 1) instead of one per 24 hours. A failed run no longer blocks every later attempt in the same process until a day after the first download.
- `Apply` waits on the limiter with the job context. The 5-minute cap on that wait is gone: it existed to stop a 24-hour reservation from holding a worker goroutine, and the longest wait is now about one minute.

## Key decisions

- A short limiter, not removal and not a token spent only on success. PLAN.md §3 (feed adapters: each adapter manages its own client-side rate limiter) asks for a limiter per adapter. The other throttles do not cover every case: `FailJob` retries after 2 and 4 seconds, `BackoffUntil` gates only the scheduler and not the job queue's own retries, and a failed write of the sync state leaves no backoff at all. A token spent only on success would leave those retries unthrottled.
- One minute. It spreads the three job attempts over about two minutes, so a short upstream fault can clear before the job goes dead, and it stays far below the 10-minute job limit that every wait counts against.
- Successful runs stay at one download a day through the same-day cursor check and the scheduler's 24-hour interval from `LastSuccessAt`. Neither depends on the limiter.
- A run that applied the file but could not persist its cursor now re-downloads on retry. The apply is idempotent (`IS DISTINCT FROM` guards), so this costs one extra download and repairs the cursor.

## Gotchas

- `x/time/rate` has no injectable clock. The tests call `AllowN(future, 0)`, which credits the refill up to `future` and spends nothing, to observe a later attempt against the limiter that `New` builds, without sleeping.
- The 2026-11-07 entry on the EPSS apply batching lists a database outage as a failed run. It is not one: `applyRows` returns an error only when the context has ended, so during an outage every row is logged and skipped and `Apply` returns the new cursor (see Known limits).

## Known limits

- A database outage during the apply, with the job context still live, is recorded as a successful run. Every row is skipped with a warning and the cursor advances. If the file is dated today, the same-day cursor check then skips it until the next file. This change does not alter that behaviour.
- The limiter is in-process, so a restart or a second worker process starts with a full token. The job lock key (`feed:epss`) still allows one EPSS job at a time.

## Quality checks

- `TestApply_FailedRunSucceedsOnLaterAttempt` failed before the change for both failure paths (HTTP 500 from upstream, and the job context ending after the download) with `epss: rate limit: rate: Wait(n=1) would exceed context deadline`, and passes after it.
- `TestApply_RetrySoonerThanDownloadInterval_DoesNotDownload` also passes on the old limiter, so it was break-tested with `rate.Inf` and failed with `second Apply error = epss: HTTP 500, want a rate limit error`.
- `go test ./internal/feed/epss/ ./internal/ingest/ -count=1` passes with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host).
- `golangci-lint run ./internal/feed/epss/... ./internal/ingest/...` reports 0 issues.
