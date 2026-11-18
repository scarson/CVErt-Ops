# Notify — Digests No Longer Dropped While the Previous Digest Is Pending

> **Date:** 2026-11-03
> **Branch:** `fix/digest-pending-drop`
> **Source:** follow-up to the digest re-scan window fix (NOTIFY-21): a digest run whose previous digest for the same report and channel was still pending inserted nothing, and the cursor moved past its CVEs

## What was built

| Part | Files | Description |
|---|---|---|
| Migration | `migrations/000049_drop_pending_digest_index.{up,down}.sql` | Drops the partial unique index `uq_deliveries_pending_digest` on pending digest rows per `(report_id, channel_id)` |
| Insert | `internal/store/queries/notification_deliveries.sql` | `InsertDigestDelivery` is a plain insert, one row per digest run and channel |
| Pitfall | `dev/implementation-pitfalls.md` NOTIFY-22 | The drop, the retry conflict, and the rejected alternatives |

## Key implementation decisions

- **One row per digest run, not a merge into the pending row**: each digest keeps its own retry count, backoff and delivery history. A merge (the alert debounce pattern) would give new CVEs the old row's attempt count and backoff and keep the retry conflict below.
- **Retry conflict fixed by the same change**: the pending-only index did not cover `processing` rows, so a digest inserted while the previous one was in flight made that delivery's `RetryDelivery` fail with 23505 and leave it in `processing`. `TestRetryDigestDelivery_NewerDigestPending` reproduces it.
- **The `completeDigestDeliveries` test helper is gone**: it existed only to clear the pending row that made the next digest's insert a no-op.

## Gotchas discovered

- **The alert debounce index has the same retry conflict.** `uq_deliveries_pending_alert` also covers only `pending`, so an alert row that fails while a newer alert row for the same rule and channel is pending cannot go back to `pending`, and `ResetStuckDeliveries` and `ReplayDelivery` can hit the same 23505. Not fixed here.
- **`ClaimDueReports` releases its row lock when its transaction commits**, before the digest runs. Two worker processes (`serve` and `worker` both start one) can run the same report. The dropped index made a second insert a no-op only while the first row was still `pending`, so this was already able to produce duplicate digests. Not fixed here.

## Quality checks

- **New tests:** `TestWorker_Digest_PreviousDeliveryPending` (notify), `TestRetryDigestDelivery_NewerDigestPending` (store), and `TestInsertDigestDelivery` now expects two pending rows. All three failed before the change.
- **golangci-lint:** 0 issues on `internal/notify` and `internal/store`.
- **Tests run locally:** the full `internal/notify` package, and `internal/store` tests matching `deliver|digest|report`, because of Docker contention on the dev host. The migration's down file was not exercised.
