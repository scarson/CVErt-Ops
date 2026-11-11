# MSRC pages its CSAF downloads

## What was built

- The MSRC adapter's `Fetch` merges the CSAF files listed in `changes.csv` in (timestamp, path) order, 100 files per page, and sets `LastPage` only when no files are left. The cursor names the last file merged: `last_updated` and a new `last_path`.
- FEED-19 in `dev/implementation-pitfalls.md` (one page per `Fetch`) now names the file-list form of the flaw and the need for a tie-break in the cursor.

## Why

The full live ingest for the version check plan's Phase 2 ran MSRC for 32 hours and stored nothing: 15 jobs, all failed, an empty cursor. `changes.csv` lists every CSAF file MSRC publishes, 10,146 on 2026-11-11, and `Fetch` downloaded all files after the cursor as one page. At one request per second the first sync needs nearly three hours, and a job is capped at 10 minutes. Each job ended in one of three ways: the time limit (5 jobs), HTTP 429 (8), or HTTP 502 (2). None of them saved anything, so every job started again from the first file, and the repeated bursts kept MSRC's rate limit in force.

The limit was short-lived, not a block: a request three minutes after the worker's last 429 returned 200.

## Decisions and gotchas

- `changes.csv` lists newest first, and 1,179 files share one timestamp, so a timestamp alone cannot say where a page ended. The path breaks ties.
- A cursor written by the earlier code has `last_updated` and no path. It now sorts before every file at that timestamp, so those files are merged once more. Merges are idempotent, and no deployment has such a cursor: none exists in the kept full-ingest database, where MSRC never finished a sync.
- A page of 100 takes about 100 seconds at one request per second, inside the handler's three-minute reserve per page (`pageReserve`).
- Not changed: a job that saves pages and then gets an HTTP 429 still counts as a failure, and the backoff doubles with each failure up to about 8.5 hours. If MSRC's limit is reached often in one job, the first sync will be slow. The limit's size is unknown; measure it on the kept database before changing the rate or the handler.

## Quality checks

- `TestFetch_PagesInTimestampThenPathOrder` and `TestFetch_ResumesPartwayThroughSharedTimestamp` failed before the change and pass after it. `TestFetch_ShortCircuit` now gives its cursor a path, because a cursor without one sorts before the file at its own timestamp.
- `go test ./internal/feed/msrc/ -count=1` passes (16 tests). `golangci-lint run ./internal/feed/msrc/...` reports 0 issues. The full suite result is in the pull request.
