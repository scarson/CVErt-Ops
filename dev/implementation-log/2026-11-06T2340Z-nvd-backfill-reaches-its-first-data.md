# NVD backfill reaches its first data

## What was built

- `Adapter.Fetch` in `internal/feed/nvd/adapter.go` walks past empty windows to the next page with data. The per-request work moved to `fetchPage`, so each response body closes on each iteration.
- `computeNextCursor` treats a window ending within `overlapDuration` of the response timestamp as caught up.
- Three new `Fetch` tests and one new `computeNextCursor` case.

## Key decisions

- Fixed in the adapter, not by relaxing the empty-page stop in `internal/ingest/handler.go`. The generic adapter's offset pagination with no `page_size` returns an ever-changing cursor on empty pages and relies on that stop, so relaxing it would loop forever on that configuration.
- The caught-up cursor's `WindowEnd` is still the response timestamp, and the next run reads that window first, so modifications after the last request are not skipped.

## Gotchas

- The ingest handler ends a run on an empty page. A fresh install reported success with 0 items and advanced one window per run. On 2026-11-06 the walk took about 6.5 minutes at 6 seconds per request, so about 65 empty windows, which at the 2-hour schedule is about 5.4 days with no NVD data.
- NVD's response timestamp advances on every call, and the old check compared it for equality with the window end. Runs never received `LastPage`; only an empty page ended them, so a run kept looping while anything had been modified in the last 15 minutes.
- Not fixed here: a first backfill hits `maxJobDuration` (10 minutes). The failure-tracking writes in the handler then use the same expired context, so `feed_sync_state` and `feed_fetch_log` do not record the failure. Progress survives through the per-page cursor checkpoint.

## Quality checks

- The new tests failed before the change and pass after it. `go test ./internal/feed/... ./internal/ingest/...` passes.
- On a local production stack with the live NVD API, the job walked the empty windows and stored data from the first non-empty window. Scored CVEs from it compared clean against the generated Go client's types.
