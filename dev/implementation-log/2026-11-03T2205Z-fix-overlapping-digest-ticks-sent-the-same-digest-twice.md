# Fix — Overlapping Digest Ticks Sent the Same Digest Twice

> **Date:** 2026-11-03
> **Branch:** `claude/affectionate-pascal-f8563c` (from `dev` at `5bc7f99`)

`ClaimDueReports` committed its `FOR UPDATE SKIP LOCKED` claim before the digest ran, and only the final `AdvanceReport` moved `next_run_at` out of the due window. With two notify workers live (`serve` and `worker` both start one), a tick between the claim and the advance claimed the same report again and sent its digest twice. See `dev/implementation-pitfalls.md` NOTIFY-24 (digest claim held for the whole run).

## What was built

| Feature | Files | Description |
|---|---|---|
| One transaction per report | `internal/store/scheduled_report.go`, `internal/store/queries/scheduled_reports.sql` | `Store.RunDueDigest` claims one due report (`ClaimDueReport`, `LIMIT 1 FOR UPDATE SKIP LOCKED`, minus a skip list) and calls the run function in the same bypass transaction; `DigestRun` exposes `CVEs`, `Channels`, `InsertDelivery`, and `Advance` on that transaction. Replaces `ClaimDueReports` and `Store.AdvanceReport` |
| Shared query helpers | `internal/store/notification_delivery.go`, `internal/store/report_channel.go` | `digestCVEs`, `insertDigestDelivery`, `listActiveChannelsForDigest` take a `*generated.Queries`; the standalone `Store` methods and `DigestRun` both call them |
| Runner loop | `internal/notify/digest.go` | `runDigest` runs up to `digestReportsPerTick` (10) reports, passing the IDs already attempted as `skip`; a failed delivery insert now fails the run instead of being logged |
| Tests | `internal/notify/worker_test.go`, `internal/store/scheduled_report_test.go` | Overlapping ticks send one digest; one tick runs every due report; claim skips non-due, paused, skipped, and held reports; a failed run leaves no deliveries and the report unadvanced; advance tests run through `DigestRun` |

## Key implementation decisions

- **Whole run in the claim transaction, not a lease** — the digest runner makes no outbound HTTP call, so holding the row lock for the CVE query (at most 500 rows) and inserts is allowed. An error or crash rolls back the inserts and the advance together, and the 60 s ticker retries. Advancing `next_run_at` in the claim was rejected: a run that failed after the claim waited a day, and inserts could still commit without the advance. A conditional advance needed the same plumbing and let the losing run do all its work first.
- **Skip list per tick** — a failed run rolls back and leaves the report due, so without `skip` the loop would claim it again up to ten times in one tick.
- **Behaviour change** — a failed per-channel insert now fails the whole run, which is retried. Previously the report advanced and that channel lost the day's digest. Postgres aborts the transaction on a failed statement, so continuing past it is not possible anyway.

## Gotchas discovered

- `pq.Array(nil)` binds as SQL `NULL`, and `id <> ALL(NULL)` matches no rows, so a nil skip list claimed nothing. `RunDueDigest` substitutes an empty slice; removing that line makes `TestRunDueDigest_ClaimsActiveDueReport` fail.
- The overlap test needs no production hook: a test transaction holds `LOCK TABLE notification_deliveries IN SHARE MODE`, so the first run stops at its delivery insert after claiming, and the test polls `pg_locks` for blocked sessions before starting the second run and before releasing the lock.

## Quality checks

- **golangci-lint run ./internal/notify/... ./internal/store/...:** 0 issues
- **Tests:** the overlap test failed 5 of 5 runs on `dev` (2 deliveries for 1 channel) and passes 5 of 5 with the fix; `go test ./internal/notify/ ./internal/store/ -count=1` passes.
