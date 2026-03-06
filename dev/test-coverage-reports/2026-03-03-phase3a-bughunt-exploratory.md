# Bug Hunt Report — Phase 3a (Exploratory)

**Date:** 2026-03-03
**Variant:** BH-F (Exploratory — depth-first, follow threads from high-risk code)

## Scope

**Packages/files analyzed:**
- `internal/notify/` — dispatcher.go, worker.go, webhook.go, email.go, client.go, template.go, render.go, digest.go
- `internal/alert/evaluator.go`
- `internal/store/notification_channel.go`, `notification_delivery.go`, `alert_rule_channel.go`
- `internal/api/channels.go`, `deliveries.go`, `alert_rules.go`
- `internal/worker/pool.go`
- `cmd/cvert-ops/main.go` (wiring)
- `internal/store/queries/notification_deliveries.sql`, `alert_rule_channels.sql`

**Exploration strategy:**
Started at the highest-risk orchestration point (worker claim/deliver loop), followed the claim→mark→deliver transaction flow into SQL queries, then moved to the dispatcher fanout path, then to the evaluator→dispatcher→delivery creation pipeline. Checked the API handlers for state machine correctness and wiring completeness.

## Bugs

### 1. Claim/mark race: duplicate deliveries possible under multi-worker deployment

**Location:** `internal/notify/worker.go:126-142`, `internal/store/notification_delivery.go:55-66,69-77`
**Severity:** significant
**Evidence:**
`runClaim` calls `ClaimPendingDeliveries` (TX 1: `SELECT ... FOR UPDATE SKIP LOCKED`) and then `MarkDeliveriesProcessing` (TX 2: `UPDATE SET status='processing'`) in **separate transactions**. The `FOR UPDATE SKIP LOCKED` lock is released when TX 1 commits. Between TX 1 commit and TX 2 begin, a concurrent worker can claim the same rows (still status='pending'), resulting in both workers delivering the same notifications.

The correct pattern is to SELECT and UPDATE atomically — either in a single transaction or as a CTE:
```sql
WITH claimed AS (
    SELECT id FROM notification_deliveries
    WHERE status = 'pending' AND send_after <= now()
    ORDER BY send_after LIMIT $1
    FOR UPDATE SKIP LOCKED
)
UPDATE notification_deliveries
SET status = 'processing', last_attempted_at = now(), updated_at = now()
FROM claimed
WHERE notification_deliveries.id = claimed.id
RETURNING ...;
```

**Impact:** In single-worker deployments (current), the race window doesn't exist because `runClaim` is called synchronously from a select loop. In multi-worker deployments (which the `SKIP LOCKED` pattern is designed for), this would cause duplicate webhook/email deliveries. The stuck-delivery reset (`ResetStuckDeliveries`) could also compound this by resetting rows that are being processed by another worker.

### 2. Activation pipeline not wired: rules stuck in 'activating' forever

**Location:** `internal/api/alert_rules.go:240-262`, `internal/api/alert_rules.go:459-492`, `cmd/cvert-ops/main.go:114-115,174`
**Severity:** significant
**Evidence:**
When `createAlertRuleHandler` sets `status = "activating"` (line 240) or `updateAlertRuleHandler` transitions to `"activating"` (lines 471, 479), no activation job is enqueued. Searching the entire codebase for `EnqueueJob` calls finds only `retention_cleanup` (worker.go:371). The worker pool registers handlers for `feed_ingest` and `retention_cleanup` only (main.go:115, 174) — no `alert_activation` handler.

The evaluator defines `EvaluateActivation()` and `activationQueue = "alert_activation"`, and `SweepZombieActivations` queries the `alert_activation` queue — but the end-to-end pipeline (enqueue job → poll queue → call `EvaluateActivation`) is missing.

**Impact:** Any alert rule created with `enabled=true` gets status "activating" and stays there permanently. It never transitions to "active" and is never evaluated by the batch or realtime paths (which filter for `status='active'`). Rules created with `enabled=false` (status "draft") work correctly — they just never activate.

### 3. Replay rate limit consumed on no-op replays

**Location:** `internal/api/deliveries.go:288-298`
**Severity:** minor
**Evidence:**
`replayDeliveryHandler` calls `checkReplayLimit(orgID)` at line 288 *before* calling `ReplayDelivery`. The `ReplayDelivery` SQL (notification_deliveries.sql:93-100) only updates rows `WHERE status IN ('failed', 'cancelled')`. If the delivery doesn't exist, belongs to another org, or is in a non-replayable state (pending, processing, succeeded), the UPDATE is a no-op — but the rate limit counter was already incremented.

A user could accidentally or maliciously exhaust their 10-per-hour replay quota by replaying deliveries that aren't in a replayable state.

**Impact:** Org admins may find themselves rate-limited after attempting replays on non-failed deliveries, with no way to tell why their replays aren't working. The correct fix is to check the delivery exists and is replayable *before* consuming the rate limit, or to decrement on no-op.

### 4. `createAlertRuleHandler` returns 201 for activating rules, docstring says 202

**Location:** `internal/api/alert_rules.go:160-162,262`
**Severity:** minor
**Evidence:**
The handler docstring says "Returns 201 for draft rules, 202 for rules entering activation scan." The code always returns `http.StatusCreated` (201) at line 262 regardless of whether `status = "activating"` or `status = "draft"`. This is related to bug #2 — since no activation scan is actually queued, returning 201 is arguably correct, but the docstring is misleading.

**Impact:** API consumers relying on the docstring to distinguish draft vs. activating creation responses would get the wrong status code. If/when the activation pipeline is wired, the status code logic needs to be added.

## Design Concerns

### Silent cursor parameter ignoring in list deliveries
`listDeliveriesHandler` (deliveries.go:145-160) requires both `after_created_at` AND `after_id` to apply keyset pagination. If only `after_created_at` is provided without `after_id`, the parameters are silently ignored and the first page is returned. No error or warning is emitted. This could confuse API consumers who provide only one cursor parameter expecting pagination to work.

### Per-org semaphore map grows unbounded
`Worker.sems` (worker.go:40-41) lazily creates per-org semaphore channels but never removes them. In a multi-tenant deployment with many orgs, this map grows monotonically. Each entry is small (a buffered channel), but the map itself is never pruned. Not a correctness issue, but a slow memory leak proportional to the number of distinct orgs that have ever had deliveries.

### Webhook HMAC signed with empty key when secret is somehow empty
`Send` (webhook.go:57) calls `hmac.New(sha256.New, []byte(cfg.SigningSecret))` unconditionally. If `SigningSecret` is empty (e.g., due to a data migration issue or a bug in secret generation), the webhook is still sent with a valid `X-CVErtOps-Signature` header — but the HMAC is keyed with an empty byte slice, which any attacker can reproduce. Current code always generates secrets for webhook channels, so this isn't exploitable today, but it's a fragile assumption with no defensive check.