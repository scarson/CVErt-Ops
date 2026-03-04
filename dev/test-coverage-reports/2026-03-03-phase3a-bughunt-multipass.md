# Bug Hunt Report — Phase 3a (Multi-Pass)

## Scope
Packages/files analyzed:
- `internal/notify/` — dispatcher.go, client.go, webhook.go, email.go, template.go, render.go, digest.go, worker.go
- `internal/alert/evaluator.go`
- `internal/store/notification_channel.go`
- `internal/store/alert_rule_channel.go`
- `internal/store/notification_delivery.go`
- `internal/api/channels.go`
- `internal/api/deliveries.go`
- `internal/api/alert_rules.go`

All five passes performed: Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

## Bugs

### 1. createAlertRuleHandler always returns 201, never 202 for activating rules
**Location:** internal/api/alert_rules.go:262
**Severity:** significant
**Evidence:** The handler's godoc says "Returns 201 for draft rules, 202 for rules entering activation scan." CLAUDE.md architecture notes say "handler inserts rule with `status='activating'`, enqueues scan job, returns 202 immediately." But the code always writes `http.StatusCreated` (201):
```go
entry := alertRuleToEntry(*row)
writeJSON(w, http.StatusCreated, entry)  // always 201
```
When `req.Enabled=true`, the status is set to `"activating"` (line 240) but the response code is still 201.
**Impact:** API consumers expecting 202 to distinguish "rule saved as draft" from "rule saved and activation scan queued" cannot tell the difference. Clients polling for activation completion would need to check the status field instead of relying on the HTTP status code, breaking the documented API contract.
**Found in:** Pass 1 — Contract Violations

### 2. replayDeliveryHandler returns 204 for non-existent or non-replayable deliveries
**Location:** internal/api/deliveries.go:275-300
**Severity:** minor
**Evidence:** The handler calls `srv.store.ReplayDelivery(r.Context(), id, orgID)` which silently no-ops when the delivery doesn't exist or is not in a replayable state (`ReplayDelivery` store method: "No-ops silently if the delivery is not in a replayable state"). The handler then returns 204 unconditionally:
```go
if err := srv.store.ReplayDelivery(r.Context(), id, orgID); err != nil {
    // only catches DB errors, not "not found"
}
w.WriteHeader(http.StatusNoContent) // always 204
```
Additionally, `checkReplayLimit(orgID)` (line 288) increments the rate limit counter *before* verifying the delivery exists. Ten requests to replay non-existent IDs exhaust the 10/hour rate limit, blocking legitimate replays.
**Impact:** Users get false confirmation that a replay was initiated. Rate limit budget is wasted on no-op operations. An attacker could trivially exhaust another org member's replay budget by sending 10 requests with random UUIDs.
**Found in:** Pass 1 — Contract Violations

### 3. Delivery list pagination emits phantom last page
**Location:** internal/api/deliveries.go:203-207
**Severity:** minor
**Evidence:** `listDeliveriesHandler` uses `len(rows) == limit` to decide whether to emit a `next_cursor`:
```go
if len(rows) == limit {
    last := rows[len(rows)-1]
    cursor := encodeDeliveryCursor(last.CreatedAt, last.ID)
    resp.NextCursor = &cursor
}
```
By contrast, `listAlertRulesHandler` (internal/api/alert_rules.go:324-337) correctly uses the `limit+1` strategy:
```go
rows, err := srv.store.ListAlertRules(..., limit+1)
if len(rows) > limit {
    rows = rows[:limit]
    ...
}
```
When there are exactly `limit` total delivery rows, `listDeliveriesHandler` emits a `next_cursor` that leads to an empty page. The alert rules handler avoids this by fetching one extra row.
**Impact:** Clients paginating through deliveries waste one extra API call on the phantom empty page. Not a data loss issue but a deviation from the correct sibling pattern.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### 4. Deterministic email delivery errors retried instead of immediately exhausted
**Location:** internal/notify/worker.go:186-204
**Severity:** significant
**Evidence:** The `deliver` method checks `isPermanentSMTPError` (line 188) to decide whether to exhaust immediately. But several error classes from `deliverEmail` are deterministic/permanent yet don't match any SMTP 5xx code:
- Template rendering failure (`"render email template: ..."`) — same data + same template always fails (worker.go:289)
- Payload unmarshal failure (`"unmarshal delivery payload: ..."`) — corrupted JSON never self-heals (worker.go:237)
- Empty recipients (`"email channel has no recipients"`) — channel config won't change between retries (worker.go:231)
- Config parse failure (`"parse email config: ..."`) — corrupted channel config won't change (worker.go:228)

All four are retried up to `MaxAttempts` with exponential backoff:
```go
nextAttempt := int(row.AttemptCount) + 1
if nextAttempt >= w.cfg.MaxAttempts {
    w.exhaust(ctx, row.ID, sendErr.Error())
    return
}
backoff := w.backoffSeconds(nextAttempt)
w.store.RetryDelivery(ctx, row.ID, backoff, sendErr.Error())
```
**Impact:** Each permanent email error burns the full retry budget (e.g., 5 retries × exponential backoff) before being exhausted. During this window, the delivery occupies a semaphore slot on each attempt, reducing throughput for legitimate deliveries in the same org. With a 10-second base backoff and 5 max attempts, the delivery blocks for ~5 minutes before finally being exhausted.
**Found in:** Pass 3 — Failure Mode Reasoning

### 5. Claim/mark-processing TOCTOU allows duplicate deliveries with multiple workers
**Location:** internal/notify/worker.go:125-155 + internal/store/notification_delivery.go:55-77
**Severity:** significant
**Evidence:** `runClaim` performs two separate transactions sequentially:
1. `ClaimPendingDeliveries` (store line 57) — opens a `withBypassTx`, selects rows with `FOR UPDATE SKIP LOCKED`, commits the transaction (releasing the row locks), and returns the rows.
2. `MarkDeliveriesProcessing` (store line 70) — opens a new `withBypassTx`, updates those IDs to `status='processing'`.

Between the commit of transaction 1 and the start of transaction 2, the deliveries are still `status='pending'` with no locks. A second worker process calling `ClaimPendingDeliveries` in this window would see the same rows (they're pending, not locked) and claim them too.

Both workers then call `MarkDeliveriesProcessing` on the same IDs. The SQL `UPDATE ... WHERE id = ANY($1)` succeeds for both (the second simply updates rows that are already "processing" — a no-op on status but still returns no error). Both workers proceed to `deliver()`, causing duplicate webhook/email sends.
```go
rows, err := w.store.ClaimPendingDeliveries(ctx, w.cfg.ClaimBatchSize)
// Transaction 1 committed — row locks released
// ← TOCTOU WINDOW: another worker can claim same rows
ids := make([]uuid.UUID, len(rows))
for i, r := range rows { ids[i] = r.ID }
if err := w.store.MarkDeliveriesProcessing(ctx, ids); err != nil { ... }
// Transaction 2 committed — rows now "processing"
```
**Impact:** With multiple worker instances (horizontal scaling), the same notification can be delivered multiple times. For webhook deliveries, the consumer sees duplicate POSTs with identical payloads and signatures. For email deliveries, recipients receive duplicate emails. The architecture note says "single static binary" suggesting single-worker deployment, but nothing enforces this constraint at the code level.
**Found in:** Pass 4 — Concurrency Reasoning

### 6. Delivery goroutine semaphore causes head-of-line blocking across orgs
**Location:** internal/notify/worker.go:144-155
**Severity:** minor
**Evidence:** The claim loop iterates all claimed deliveries sequentially, acquiring the per-org semaphore before spawning each goroutine:
```go
for _, row := range rows {
    row := row
    sem := w.semaphore(row.OrgID)
    sem <- struct{}{} // blocking acquire
    w.wg.Add(1)
    go func() { ... }()
}
```
If org A's semaphore is full (all `MaxConcurrentPerOrg` slots occupied), the blocking `sem <- struct{}{}` pauses the entire loop. Deliveries for org B, C, etc. later in the batch wait behind org A's semaphore even though their semaphores may have free slots.
**Impact:** A single high-volume org can delay delivery for all other orgs in the same batch. With `ClaimBatchSize=50` and one org dominating the batch, other orgs' deliveries wait until org A's in-flight deliveries complete (up to 10s webhook timeout + stuck-reset threshold). Eventual delivery is guaranteed, but latency for low-volume orgs increases under load.
**Found in:** Pass 4 — Concurrency Reasoning

### 7. Batch evaluator advances cursor even when rule evaluation fails mid-event-insert
**Location:** internal/alert/evaluator.go:126-143
**Severity:** minor
**Evidence:** In `EvaluateBatch`, when `evaluateRule` returns an error mid-way (e.g., `InsertAlertEvent` fails at line 389 after some events are already committed), the error is logged but the loop continues to the next rule, and the cursor always advances:
```go
for i := range rules {
    rule := &rules[i]
    ...
    matchCount, partial, candidatesEval, evalErr := e.evaluateRule(...)
    if evalErr != nil {
        e.log.Error("evaluate rule batch", ...) // logged, not returned
    }
    // Run row written regardless
    status, errMsg := runStatus(partial, evalErr)
    if run, runErr := ...; runErr == nil {
        _ = e.rules.UpdateAlertRuleRun(...)
    }
}
return e.writeCursor(ctx, batchFeedName, batchTime) // cursor always advances
```
Inside `evaluateRule` (line 387-391), if `InsertAlertEvent` fails for one CVE, the function returns immediately — skipping remaining matched CVEs for that rule. The run is marked "error", but the batch cursor advances past those CVE IDs. On the next batch tick, those CVEs won't appear in the candidate set (their `date_modified_canonical` hasn't changed), so the skipped events are permanently lost.
**Impact:** A transient DB error during event insertion (e.g., brief connection drop) silently loses alert events for any matched CVEs that follow the failed insert. The run is marked "error" but no automatic retry mechanism re-evaluates the skipped CVEs. The same pattern exists in `EvaluateEPSS` (lines 168-186).
**Found in:** Pass 5 — Error Propagation

## Design Concerns

### Webhook config parse error masked by downstream failure
`deliverWebhook` (worker.go:207-220) silently ignores `json.Unmarshal` errors on channel config with an `//nolint:errcheck` comment, relying on `Send` to fail with an empty URL. This means corrupted webhook configs produce cryptic errors like `"build webhook request: parse \"\" ..."` rather than `"parse webhook config: ..."`. Combined with bug #4 (permanent errors retried), a corrupted webhook config burns the full retry budget with unhelpful error messages before being exhausted. The sibling `deliverEmail` properly validates config up front.

### No recovery mechanism for partially-evaluated rules
When `evaluateRule` fails mid-way through matched CVEs (bug #7), the successfully-inserted events have already triggered fanout, but the remaining matched CVEs are skipped. The cursor advances, and no mechanism re-evaluates the window. A per-rule "last successful evaluation" cursor (separate from the global batch cursor) would allow re-evaluation of failed rules without re-evaluating all rules.

### Backoff can produce zero-second delays
`backoffSeconds` (worker.go:317-322) computes `int(base * 2^(attempt-1) * jitter)` where jitter is in [0.5, 1.5). With `BackoffBaseSeconds=1` and `attempt=1`: `int(1.0 * 1.0 * 0.5) = 0`. A zero-second backoff means the delivery is immediately eligible for re-claim on the next 5-second tick, defeating the purpose of exponential backoff for the first retry.

