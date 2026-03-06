# Bug Hunt Report — Phase 3b (Exploratory)

**Date:** 2026-03-03
**Variant:** BH-I (Exploratory — depth-first, follow threads from high-risk code)

## Scope

Packages/files analyzed:

| File | Risk | Depth |
|------|------|-------|
| `internal/notify/worker.go` | High — pipeline orchestrator, multi-step claim→deliver→retry flow | Deep |
| `internal/notify/digest.go` | High — cross-package coordination, time/timezone logic | Deep |
| `internal/store/notification_delivery.go` | High — delivery queue state machine, SQL boundary | Deep |
| `internal/api/deliveries.go` | Medium — pagination cursor, nullable field rendering | Deep |
| `internal/api/reports.go` | Medium — PATCH semantics for nullable fields | Deep |
| `internal/api/channels.go` | Medium — validation, SSRF checks | Read |
| `internal/store/notification_channel.go` | Low — straightforward CRUD wrapper | Read |
| `internal/store/scheduled_report.go` | Low — straightforward CRUD wrapper | Read |
| `internal/store/report_channel.go` | Medium — worker vs API method selection | Read |
| `internal/notify/render.go` | Low — pure rendering, no state | Read |
| `internal/notify/template.go` | Low — data structs, no logic risk | Read |
| `internal/notify/email.go` | Low — thin SMTP wrapper | Read |
| `internal/api/server.go` | Low — route wiring, reviewed for RBAC correctness | Read |

**High-risk entry points explored deeply:** The delivery worker's claim→mark→deliver flow (worker.go + notification_delivery.go + the underlying SQL) and the digest runner's cross-transaction coordination (digest.go + report_channel.go). These are the two multi-step flows that coordinate state across transactions and packages.

## Bugs

### 1. Delivery claim/mark race allows duplicate deliveries under concurrent workers

**Location:** `internal/notify/worker.go:125-155` + `internal/store/notification_delivery.go:55-66`
**Severity:** significant
**Evidence:**

`runClaim` performs claim and mark in two separate transactions:

```go
// Transaction 1: SELECT ... FOR UPDATE SKIP LOCKED (locks released on commit)
rows, err := w.store.ClaimPendingDeliveries(ctx, w.cfg.ClaimBatchSize)
// ...
// Transaction 2: UPDATE status = 'processing'
if err := w.store.MarkDeliveriesProcessing(ctx, ids); err != nil {
```

`ClaimPendingDeliveries` runs in a `withBypassTx` that commits before `MarkDeliveriesProcessing` opens its own transaction. Between the two calls, the rows are unlocked and still `status = 'pending'`. A concurrent worker calling `ClaimPendingDeliveries` during this window will see and claim the same rows (they're not locked and not yet 'processing').

The `FOR UPDATE SKIP LOCKED` pattern is specifically designed for multi-worker queue consumption, implying the design supports concurrent workers. But the two-transaction split breaks the mutual-exclusion guarantee that `SKIP LOCKED` provides.

**Impact:** Concurrent workers can double-claim delivery rows, resulting in duplicate webhook/email deliveries to end users. The fix is to combine claim+mark into a single atomic operation (e.g., a CTE that selects and updates in one statement).

---

### 2. Digest deliveries render `rule_id` as nil UUID instead of null

**Location:** `internal/api/deliveries.go:171-174` (listDeliveriesHandler) and `internal/api/deliveries.go:238-241` (getDeliveryHandler)
**Severity:** minor
**Evidence:**

The `deliveryEntry` struct declares `RuleID` as a non-nullable `string`:

```go
type deliveryEntry struct {
    // ...
    RuleID    string  `json:"rule_id"`
    // ...
}
```

And the handler unconditionally renders it from `uuid.NullUUID`:

```go
RuleID: row.RuleID.UUID.String(),
```

For digest deliveries, `rule_id` is NULL in the database (the `InsertDigestDelivery` SQL omits `rule_id`). When `row.RuleID.Valid` is false, `row.RuleID.UUID` is the zero-value `uuid.Nil`, so the API returns:

```json
{"rule_id": "00000000-0000-0000-0000-000000000000"}
```

instead of `null` or omitting the field.

**Impact:** API clients cannot distinguish "this delivery was for a digest report (no rule)" from "this delivery was for the rule with ID 00000000-..." — incorrect API contract. Should be `*string` with `omitempty`, only populated when `row.RuleID.Valid` is true.

---

### 3. PATCH cannot clear `severity_threshold` back to "all severities"

**Location:** `internal/api/reports.go:282-288` (patchReportHandler)
**Severity:** minor
**Evidence:**

The PATCH body declares `SeverityThreshold` as `*string`:

```go
type patchReportBody struct {
    SeverityThreshold *string `json:"severity_threshold"`
}
```

In Go's JSON unmarshaling, both "field absent" and `"severity_threshold": null` decode to a nil `*string`. The handler only acts when the pointer is non-nil:

```go
if req.SeverityThreshold != nil {
    if !validSeverityThresholds[*req.SeverityThreshold] {
        // → 422
    }
    params.SeverityThreshold = sql.NullString{String: *req.SeverityThreshold, Valid: true}
}
```

- Sending `null` → nil pointer → condition skipped → existing value preserved (no clear)
- Sending `""` → non-nil pointer → `validSeverityThresholds[""]` is false → 422 error
- Omitting the field → nil pointer → condition skipped → existing value preserved

There is **no way** to reset `severity_threshold` to NULL (all severities) once it has been set. The user must delete and recreate the report.

**Impact:** Users who set a severity threshold on a digest report cannot undo it without deleting the report. This is a usability bug caused by the well-known Go JSON `*string` ambiguity between "not provided" and "set to null".

## Design Concerns

### Digest runner calls API-scoped method instead of its dedicated bypass-RLS method

**Location:** `internal/notify/digest.go:162` calls `w.store.ListChannelsForReport(ctx, report.OrgID, report.ID)`

The `ListChannelsForReport` method uses `withOrgTx` (intended for API handlers), but the digest runner is a background worker. A dedicated `ListActiveChannelsForDigest` method exists in `internal/store/report_channel.go:63` that uses `withBypassTx` and is documented as "must only be called from the digest runner". The digest runner calls the wrong one.

Functionally, `withOrgTx` still works because it accepts an explicit `orgID` parameter and sets the RLS context correctly. But this is architecturally inconsistent with the convention that workers use bypass-RLS methods (every other store call in the digest flow uses `withBypassTx`). If the RLS policy or transaction helper semantics change, this call would be the first to break.

### Partial pagination cursor silently ignored

**Location:** `internal/api/deliveries.go:145-159`

If a client provides `after_created_at` without `after_id`, the cursor is silently ignored and the query defaults to `(time.Now(), uuid.Max)` — effectively returning results from the beginning. The `next_cursor` response encodes both values as a single `time/uuid` string, so a well-behaved client splitting that cursor would always provide both. But the silent fallback could mask client bugs and complicate debugging.
