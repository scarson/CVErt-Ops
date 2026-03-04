# Bug Hunt Report — Phase 3a (BH-D Holistic)

**Date:** 2026-03-03
**Variant:** BH-D — Holistic (read all source, then reason)
**Analyst:** Claude (Opus 4.6)

## Scope

Packages/files analyzed (source only, no test files):

- `internal/notify/dispatcher.go` — fanout from alert events to delivery rows
- `internal/notify/client.go` — SSRF-safe HTTP client construction
- `internal/notify/webhook.go` — outbound webhook delivery + HMAC signing
- `internal/notify/email.go` — SMTP email delivery
- `internal/notify/template.go` — template data structs + conversion
- `internal/notify/render.go` — HTML/text template rendering
- `internal/notify/digest.go` — digest report runner
- `internal/notify/worker.go` — delivery worker (claim → dispatch → retry/exhaust)
- `internal/alert/evaluator.go` — alert evaluation paths (realtime, batch, EPSS, activation)
- `internal/store/notification_channel.go` — channel CRUD + secret rotation
- `internal/store/alert_rule_channel.go` — rule ↔ channel M:M bindings
- `internal/store/notification_delivery.go` — delivery job queue operations
- `internal/api/channels.go` — HTTP handlers for channel CRUD
- `internal/api/deliveries.go` — HTTP handlers for delivery history + replay
- `internal/api/alert_rules.go` — HTTP handlers for alert rule CRUD + DSL validation

Additionally consulted: `internal/worker/pool.go`, `internal/worker/job.go`, `cmd/cvert-ops/main.go` (handler registration), relevant generated SQL in `internal/store/generated/`, `internal/store/cve.go`, `internal/store/scheduled_report.go`, `internal/store/org.go`.

**Approach:** Read every source file into context. Then traced the full lifecycle of each major flow (alert rule creation → activation → evaluation → fanout → delivery → retry/exhaust, and digest report → claim → CVE query → delivery). Looked for contract violations, missing steps, race conditions, and error handling gaps.

## Bugs

### 1. Activation jobs never enqueued — rules stuck in "activating" forever

**Location:** `internal/api/alert_rules.go:240-262` (create), `internal/api/alert_rules.go:459-505` (update)
**Severity:** critical
**Evidence:**

`createAlertRuleHandler` sets `status = "activating"` when `req.Enabled == true` (line 240-243) and `updateAlertRuleHandler` transitions to `"activating"` on DSL changes to active rules or when enabling draft/disabled/error rules (lines 470-480). Neither handler enqueues an activation job into the `job_queue`.

The evaluator expects to be called by a worker processing `alert_activation` jobs (`evaluator.go:190`), the `activationQueue` constant is defined (`evaluator.go:25`), and `SweepZombieActivations` queries `job_queue WHERE queue = 'alert_activation'` (`evaluator.go:255-263`). But `cmd/cvert-ops/main.go` only registers `feed_ingest` and `retention_cleanup` handlers — no `alert_activation` handler is registered. No code path in the API handlers calls `EnqueueJob` for activation.

**Impact:** Any alert rule created with `enabled: true` or re-enabled via PATCH enters "activating" status and stays there permanently. The rule never transitions to "active" and never evaluates against CVEs. The activation scan (which builds the baseline of existing matches to suppress future duplicate alerts) never runs. This is the primary alert rule lifecycle — it's completely broken for enabled rules.

### 2. createAlertRuleHandler always returns 201, not 202 for activating rules

**Location:** `internal/api/alert_rules.go:261-262`
**Severity:** significant
**Evidence:**

The handler's doc comment states: "Returns 201 for draft rules, 202 for rules entering activation scan." PLAN.md §10 specifies: "handler inserts rule with status='activating', enqueues scan job, returns 202 immediately."

The code unconditionally returns `http.StatusCreated` (201):
```go
entry := alertRuleToEntry(*row)
writeJSON(w, http.StatusCreated, entry)
```

There is no conditional on `status` to return 202.

**Impact:** API clients cannot distinguish between a draft rule (201, immediately usable) and an activating rule (should be 202, processing in background). This breaks the documented API contract. Related to bug #1 — when the activation job is added, the response code must also be fixed.

### 3. Delivery worker goroutines use parent context — duplicate deliveries on shutdown

**Location:** `internal/notify/worker.go:148-154`
**Severity:** significant
**Evidence:**

`Worker.Start(ctx)` runs a `for/select` loop with the process-level context. `runClaim` spawns goroutines that pass this same `ctx` to `deliver`:

```go
go func() {
    defer func() { <-sem }()
    defer w.wg.Done()
    w.deliver(ctx, row)  // ← uses parent ctx
}()
```

When SIGTERM fires, `ctx` is cancelled. The select loop exits and calls `w.wg.Wait()`. But the in-flight goroutines' `ctx` is already cancelled. Any DB call within `deliver` — `GetNotificationChannelForDelivery`, `CompleteDelivery`, `RetryDelivery`, `ExhaustDelivery` — will fail with a context cancellation error.

The failure path in `deliver` calls `exhaust()` or `RetryDelivery()`, which also fail (same cancelled ctx). The delivery remains in "processing" status. On next startup, after `StuckThreshold` (default 2 minutes), `ResetStuckDeliveries` resets it to "pending" and it's re-delivered.

The project's own architecture note states: "Background goroutines from HTTP handlers: `context.WithoutCancel(r.Context())`" — the same principle applies to worker goroutines.

**Impact:** Every in-flight delivery at shutdown time will be delivered a second time after restart. For webhooks, this is a duplicate POST (consumers should be idempotent, but not all are). For emails, recipients receive duplicate emails.

### 4. Replay handler returns 204 for non-existent or non-replayable deliveries

**Location:** `internal/api/deliveries.go:275-300`
**Severity:** minor
**Evidence:**

`replayDeliveryHandler` calls `srv.store.ReplayDelivery(r.Context(), id, orgID)` and returns 204 on success. The underlying SQL:

```sql
UPDATE notification_deliveries
SET status = 'pending', attempt_count = 0, ...
WHERE id = $1 AND org_id = $2
  AND status IN ('failed', 'cancelled')
```

If the delivery doesn't exist, belongs to a different org, or is in a non-replayable status (`pending`, `processing`, `succeeded`), the UPDATE affects 0 rows. The sqlc-generated `ReplayDelivery` uses `ExecContext` and doesn't check `RowsAffected`. The handler returns 204 regardless.

Additionally, `checkReplayLimit(orgID)` is called **before** verifying the delivery exists or is replayable. A non-existent delivery ID consumes a rate limit token (max 10/hour).

**Impact:** API clients can't distinguish between a successful replay and a no-op. Rate limit tokens are consumed by failed replay attempts, potentially blocking legitimate replays within the same hour window.

### 5. Claim and MarkProcessing in separate transactions — concurrent-worker race

**Location:** `internal/notify/worker.go:125-143`
**Severity:** minor
**Evidence:**

`runClaim` calls `ClaimPendingDeliveries` (wrapped in `withBypassTx` — transaction 1 commits on return), then `MarkDeliveriesProcessing` (wrapped in `withBypassTx` — transaction 2). Between these two calls, claimed rows are:
- Status: still `pending` (unchanged)
- Not locked (transaction 1 committed, releasing `FOR UPDATE` locks)

A concurrent worker instance could claim the same rows in this window. The current single-worker architecture makes this unlikely, but it's incorrect for horizontal scaling.

**Impact:** With multiple worker processes (future scaling), the same delivery could be claimed and dispatched twice, causing duplicate webhook/email deliveries. With a single worker process, the window is microseconds and practically unreachable.

## Design Concerns

### Cancelled context propagation in worker lifecycle

Beyond the specific bug in delivery goroutines (bug #3), the broader pattern of passing the process-level `ctx` into worker operations means that graceful shutdown abruptly cancels all in-progress work. The `wg.Wait()` call ensures goroutines finish, but their work fails because the context they depend on is already dead. A `context.WithoutCancel()` wrapper for spawned goroutines would preserve the shutdown coordination (via `wg.Wait`) while letting in-flight work complete its DB operations.

### GetCVESnapshot bypasses transaction helper convention

`Store.GetCVESnapshot` (`internal/store/cve.go:217`) queries `s.q.GetCVESnapshot` directly on the pool, bypassing the transaction helper pattern used by all other store methods. The `cves` table is global (no RLS), so this is functionally correct. But it violates the convention documented in CLAUDE.md: "Never query `s.db` directly in store methods — always use a transaction helper." If RLS were ever added to the `cves` table (unlikely but possible), this method would silently fail.

### No activation job handler registered

Related to bug #1: even if the handlers were fixed to enqueue activation jobs, `cmd/cvert-ops/main.go` doesn't register an `alert_activation` handler with the worker pool. Both the enqueue call (in API handlers) and the handler registration (in main.go) are missing. The `EvaluateActivation` evaluator method and `SweepZombieActivations` exist but are unreachable.