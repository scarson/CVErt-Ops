# Phase 3a — Notification Delivery (Webhooks)

> **Dates:** 2026-02-28
> **Branch:** `dev`
> **Commits:** `d14b411` (migrations), `77dc455`–`7b02fa7` (store), `6fd4e7c`–`283499a` (notify), `7ae85ad`–`0fa477d` (api), `5ff808b` (wiring), `83d0cf1` (quality fixes), `1c9712e`–`7d572ac` (test coverage)
> **Deliverables:** Migration 000017, notification channels CRUD, delivery dispatcher, webhook sender with HMAC, delivery worker with retry/backoff, API handlers

## Files created / modified

| File | Purpose |
|---|---|
| `migrations/000017_create_notification_tables.{up,down}.sql` | `notification_channels` (soft-delete, webhook), `alert_rule_channels` (M:M join, `org_id` denormalized), `notification_deliveries` (queue, autovacuum tuning) |
| `internal/notify/webhook.go` | `Send()` with HMAC-SHA256 signing, safeurl client, response body drain via `io.LimitReader`, denied-header filter, dual-signature for secret rotation |
| `internal/notify/dispatcher.go` | `Fanout()`: list channels → build CVE snapshot → `UpsertDelivery` per channel with debounce |
| `internal/notify/worker.go` | Five tickers (claim/stuck/recovery/digest/aiCleanup), per-org semaphore, exponential backoff with jitter |
| `internal/notify/client.go` | `BuildSafeClient()` with `MaxConnsPerHost: 50`, redirect disabled, 10s timeout |
| `internal/api/channels.go` | Channel CRUD + `validateWebhookURL` SSRF static check + `clearSecondarySecretHandler` |
| `internal/api/bindings.go` | Rule-channel `PUT/DELETE/GET` binding endpoints |
| `internal/api/deliveries.go` | List/detail/replay delivery endpoints |
| `internal/store/notification_channel.go` | Channel CRUD with `RotateSigningSecret`, `ClearSecondarySecret` |
| `internal/store/notification_delivery.go` | Claim/mark/retry/exhaust/recovery queries |
| `internal/alert/evaluator.go` | Injected `Dispatcher`, calls `Fanout` after `alert_event` commit |

## Key implementation decisions

**Two-transaction gap is intentional.** Alert events written in `bypassTx`; after commit, `Fanout()` runs in fresh `withOrgTx`. Orphaned-event recovery scan (5-min ticker) closes the gap.

**Debounce via partial unique index.** `UNIQUE (rule_id, channel_id) WHERE status = 'pending'` — multiple CVE events from same rule accumulate into one pending delivery's payload JSONB array. Deviates from PLAN.md's per-event idempotency key but provides equivalent dedup with correct debounce semantics.

**Two-step claim.** `ClaimPendingDeliveries` (`SELECT FOR UPDATE SKIP LOCKED`) + `MarkDeliveriesProcessing` (`UPDATE → processing`). Crash between steps is safe: rows stay in `pending`, never entered `processing`.

**Per-org semaphore as blocking channel send.** Intentional backpressure — bounded by delivery timeout and stuck-reset recovery.

**Secondary-secret dual-signing.** Diverges from design doc ("sender never emits secondary") — actual implementation emits `X-CVErtOps-Signature-Secondary` during rotation grace period for simpler receiver logic.

## Quality check results

**pitfall-check:** Clean.
**plan-check (§11, §16):** Found missing `MaxConnsPerHost`, secondary signing support, `validateWebhookURL` static check. All fixed in `83d0cf1`.
**security-review:** Found delivery cursor RFC3339 format mismatch (encode vs parse). Fixed.
**go test `./...`:** All tests pass.
**golangci-lint:** 0 issues.
