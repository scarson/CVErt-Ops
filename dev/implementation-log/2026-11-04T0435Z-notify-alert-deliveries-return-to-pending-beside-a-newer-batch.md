# Notify — Alert Deliveries Return to Pending Beside a Newer Batch

> **Date:** 2026-11-03
> **Branch:** `fix/alert-retry-pending-conflict` (from `dev` at `5bc7f99`, merged with `dev` at `fa42dd0`, `bfdb7ad` and `eb8b8af`)

The digest fix (PR #159) noted that the alert debounce index `uq_deliveries_pending_alert` had the same retry conflict. All five statements that move a delivery back to `pending` (worker retry, stuck-row reset, org replay, admin retry, admin bulk retry) failed with 23505 when a newer batch for the same rule and channel was pending. The two bulk statements also failed on two of their own rows. Recorded as `dev/implementation-pitfalls.md` NOTIFY-25 (alert delivery cannot return to pending beside a newer batch).

## What was built

| Feature | Files | Description |
|---|---|---|
| Open-batch index | `migrations/000050_open_alert_batch_index.*.sql` | Adds `batch_open`, backfills it for pending alert deliveries never claimed, builds `uq_deliveries_open_alert_batch` (pending, alert, `batch_open`), then drops `uq_deliveries_pending_alert` |
| Debounce upsert | `internal/store/notification_delivery.go` | `UpsertDelivery` inserts open batches and its `ON CONFLICT` targets the open-batch index |
| Closed batches | `internal/store/queries/notification_deliveries.sql`, `internal/store/queries/admin_deliveries.sql` | Claiming sets `batch_open = false`, and the five statements that return a delivery to `pending` set it false too |
| Tests | `internal/store/notification_delivery_test.go`, `internal/store/admin_delivery_test.go` | Each of the five statements with a newer batch pending or two rows for one pair. A CVE matched during a retry backoff starts its own batch, and the backoff and payload of the retrying batch are unchanged |

## Key implementation decisions

- **Closed batches are delivered separately** — a delivery back in `pending` keeps its own attempt count and backoff, as digests do after NOTIFY-22 (each digest run gets its own delivery row). Merging it into the open batch was rejected: in a sustained outage every failed send merges into the next batch, so the attempt count never reaches the limit and the payload grows without bound. Widening the index to cover `processing` was rejected because a CVE matched during a send would have no row to join. Cost: after an outage a channel can get one message per closed batch.
- **Explicit column, not `last_attempted_at IS NULL`** — the predicate would also work today, but a replay of a never-attempted cancelled delivery would reopen a batch. Only `UpsertDelivery` sets `batch_open`.
- **Deployment window** — an old binary still running after the migration fails its alert upserts (its `ON CONFLICT` predicate no longer matches a unique index) until it is replaced. The binary already requires the schema at its own version at startup.

## Quality checks

- **Tests:** the six return-to-pending tests failed with 23505 and the backoff test failed (one pending row, want two) before the fix. Migration backfill and down/up round trip checked with a throwaway test (not committed): only the never-claimed pending alert delivery is backfilled open, and the down migration rebuilds `uq_deliveries_pending_alert`.
- **Full suite** at `4490b6b` (`TESTCONTAINERS_RYUK_DISABLED=true go test ./... -count=1 -timeout=600s`): all packages pass. `cmd/cvert-ops`, `internal/api` and `web` first failed at setup because the worktree had no `web/dist`, and passed after copying it from the main checkout. After merging `dev` at `bfdb7ad`, the full suite passed again at `d575622` (35 packages). The merge of `dev` at `eb8b8af` changed documentation only.
- **golangci-lint run ./internal/store/...:** 0 issues
