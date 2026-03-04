# Bug Hunt Report — Phase 3b (Multi-Pass)

## Scope
**Packages/files analyzed:**
- `internal/store/scheduled_report.go`
- `internal/store/report_channel.go`
- `internal/store/notification_channel.go`
- `internal/store/notification_delivery.go`
- `internal/notify/email.go`
- `internal/notify/render.go`
- `internal/notify/template.go`
- `internal/notify/digest.go`
- `internal/notify/worker.go`
- `internal/api/channels.go`
- `internal/api/reports.go`
- `internal/api/deliveries.go`
- `internal/api/server.go`

**Supporting files read for cross-reference:**
- `internal/notify/dispatcher.go` (cveSnapshot type, Dispatcher)
- `internal/notify/webhook.go` (Send function)
- `internal/store/queries/notification_deliveries.sql` (claim SQL)

**Passes performed:** All five (Contract, Cross-Sibling, Failure Mode, Concurrency, Error Propagation)

## Bugs

### 1. Digest runner calls API-facing store method instead of worker method
**Location:** internal/notify/digest.go:162
**Severity:** significant
**Evidence:** The digest runner calls `w.store.ListChannelsForReport(ctx, report.OrgID, report.ID)` which uses `withOrgTx` (sets `SET LOCAL app.org_id`). However, `ListActiveChannelsForDigest` exists in `report_channel.go:63-77` specifically for this purpose — its comment says "Uses bypass RLS — must only be called from the digest runner, never from API handlers."

The digest runner is a background worker, and per project conventions (CLAUDE.md): `withOrgTx` is for API handler org-scoped queries; workers should use `withBypassTx` or `WorkerTx`. `ListActiveChannelsForDigest` was explicitly created for the digest runner and is never called anywhere.

**Impact:** Convention violation. Currently works because `withOrgTx` sets the RLS context variable on the connection, but violates the documented transaction helper selection rules. If the worker DB role permissions change or RLS policies are tightened, this could silently return zero rows. Also means `ListActiveChannelsForDigest` is dead code.
**Found in:** Pass 1 — Contract Violations

### 2. RuleID serialized as zero UUID for digest deliveries
**Location:** internal/api/deliveries.go:174, internal/api/deliveries.go:240
**Severity:** significant
**Evidence:** In both `listDeliveriesHandler` and `getDeliveryHandler`, `RuleID` is unconditionally serialized:
```go
RuleID: row.RuleID.UUID.String(),
```
`RuleID` is a `uuid.NullUUID`. For digest deliveries, `rule_id` is NULL in the database. This outputs `"00000000-0000-0000-0000-000000000000"` — a misleading zero UUID.

Compare with `ReportID` in the same handlers (deliveries.go:183-186, 250-253), which correctly checks `.Valid`:
```go
if row.ReportID.Valid {
    s := row.ReportID.UUID.String()
    entry.ReportID = &s
}
```

The struct `deliveryEntry` declares `RuleID string` (non-pointer, always present) vs `ReportID *string` (pointer, omitted when null). The same asymmetry applies.

**Impact:** API consumers see `"rule_id": "00000000-0000-0000-0000-000000000000"` for digest deliveries instead of `null` or omission. This creates confusion — clients may try to look up a rule with the zero UUID and get 404, or filter by rule_id and get unexpected results.
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### 3. PATCH reports handler cannot clear severity_threshold to NULL
**Location:** internal/api/reports.go:282-288
**Severity:** significant
**Evidence:** The patch handler checks:
```go
if req.SeverityThreshold != nil {
    if !validSeverityThresholds[*req.SeverityThreshold] {
        http.Error(w, "severity_threshold must be critical, high, medium, or low", http.StatusUnprocessableEntity)
        return
    }
    params.SeverityThreshold = sql.NullString{String: *req.SeverityThreshold, Valid: true}
}
```

Once `severity_threshold` is set to a value (e.g., "high"), there is no way to clear it back to NULL (meaning "all severities"). Sending `""` fails the `validSeverityThresholds` check. Sending `null` in JSON causes `req.SeverityThreshold` to remain `nil`, which skips the block entirely and preserves the existing value. There is no code path that sets `params.SeverityThreshold = sql.NullString{Valid: false}`.

**Impact:** A report created with `severity_threshold: "critical"` can never be changed to receive all severities — users must delete and recreate the report. This is a data model bug: the PATCH operation is not reversible for this field.
**Found in:** Pass 1 — Contract Violations

### 4. deleteReportHandler returns 204 for non-existent reports
**Location:** internal/api/reports.go:344-361
**Severity:** minor
**Evidence:** `deleteReportHandler` calls `SoftDeleteScheduledReport` directly without first checking if the report exists:
```go
func (srv *Server) deleteReportHandler(w http.ResponseWriter, r *http.Request) {
    // ... parse orgID, id ...
    if err := srv.store.SoftDeleteScheduledReport(r.Context(), orgID, id); err != nil {
        // ...
    }
    w.WriteHeader(http.StatusNoContent)
}
```

Compare with `deleteChannelHandler` (channels.go:350-360) which fetches the entity first and returns 404 if not found:
```go
current, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
// ...
if current == nil {
    http.Error(w, "not found", http.StatusNotFound)
    return
}
```

**Impact:** Clients cannot distinguish between "successfully deleted" and "didn't exist" — both return 204. API behavior is inconsistent with the channel delete endpoint. Also no audit log entry is emitted (the channel handler logs the old state for audit).
**Found in:** Pass 2 — Cross-Sibling Pattern Violations

### 5. Claim-then-mark TOCTOU race in multi-worker deployments
**Location:** internal/notify/worker.go:125-155, internal/store/queries/notification_deliveries.sql:4-10
**Severity:** significant
**Evidence:** The claim flow is two separate transactions:

**Transaction 1** (ClaimPendingDeliveries):
```sql
SELECT id, org_id, rule_id, channel_id, kind, report_id, attempt_count, payload
FROM notification_deliveries
WHERE status = 'pending' AND send_after <= now()
ORDER BY send_after LIMIT $1
FOR UPDATE SKIP LOCKED;
```
The `withBypassTx` wrapper commits this transaction, releasing the row locks.

**Transaction 2** (MarkDeliveriesProcessing):
```sql
UPDATE notification_deliveries
SET status = 'processing', last_attempted_at = now(), updated_at = now()
WHERE id = ANY($1::uuid[]);
```

Between Transaction 1 committing (releasing `FOR UPDATE` locks) and Transaction 2 executing, another worker instance can run its own `ClaimPendingDeliveries` and claim the same rows — they're still `status = 'pending'` and no longer locked.

**Impact:** In multi-worker deployments, the same delivery can be claimed and processed by multiple workers, resulting in duplicate webhook calls or duplicate emails sent to recipients. Single-worker deployments are unaffected since claim is sequential within the select loop.
**Found in:** Pass 4 — Concurrency Reasoning

## Design Concerns

### Digest fan-out failures silently advance the report window
In `digest.go:168-174`, each `InsertDigestDelivery` error is logged but execution continues. After the loop, `advanceReport` always runs, advancing `next_run_at` and `last_run_at`. If all delivery inserts fail (e.g., transient DB constraint issue), the CVE window is lost — those CVEs won't appear in the next digest run. Consider tracking whether at least one delivery succeeded before advancing.

### Replay rate limit consumed before verifying delivery is replayable
In `deliveries.go:288-298`, `checkReplayLimit(orgID)` runs before `ReplayDelivery`. If the delivery doesn't exist, belongs to a different org (filtered by RLS), or is not in a replayable state (the SQL no-ops), the rate limit slot is still consumed. An attacker could exhaust the 10/hour limit by replaying non-existent delivery IDs.

### In-memory rate limiter not effective across multiple server processes
The `replayBuckets` sync.Map in `deliveries.go:28` is process-local. If N server processes are load-balanced, the effective rate limit becomes N × 10 per hour per org rather than 10. This is acceptable for the current single-binary architecture but will need a database-backed counter if horizontal scaling is added.
