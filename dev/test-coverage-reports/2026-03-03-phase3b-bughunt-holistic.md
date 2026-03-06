# Bug Hunt Report — Phase 3b Holistic (BH-G)

## Scope

**Packages/files analyzed (13 source files):**
- `internal/store/scheduled_report.go` — scheduled report CRUD
- `internal/store/report_channel.go` — report↔channel M:M bindings
- `internal/store/notification_channel.go` — notification channel CRUD + secret rotation
- `internal/store/notification_delivery.go` — delivery queue operations
- `internal/notify/email.go` — SMTP email delivery
- `internal/notify/render.go` — template rendering
- `internal/notify/template.go` — template data structs + snapshot conversion
- `internal/notify/digest.go` — digest runner
- `internal/notify/worker.go` — delivery worker
- `internal/notify/dispatcher.go` — alert event fanout (supporting context)
- `internal/notify/webhook.go` — webhook delivery (supporting context)
- `internal/api/channels.go` — channel HTTP handlers
- `internal/api/reports.go` — scheduled report HTTP handlers
- `internal/api/deliveries.go` — delivery history HTTP handlers
- `internal/api/server.go` — route wiring

**Approach:** Read all source files, then examined cross-cutting flows: digest execution path, delivery lifecycle, PATCH semantics, secret rotation, and worker↔API boundary conventions. Verified bugs against generated SQL and design documents.

## Bugs

### 1. Digest runner calls wrong store method — uses API path instead of worker path

**Location:** `internal/notify/digest.go:162`
**Severity:** significant
**Evidence:**

The digest runner calls `ListChannelsForReport` (API-facing, `withOrgTx`) instead of `ListActiveChannelsForDigest` (worker, `withBypassTx`):

```go
// digest.go:162 — what it does:
channels, err := w.store.ListChannelsForReport(ctx, report.OrgID, report.ID)
```

The method `ListActiveChannelsForDigest` was purpose-built for this exact call site. The design document (`dev/plans/2026-02-28-phase-3b-email-templates-digests-design.md:208`) explicitly specifies:

> For each bound channel (via `ListActiveChannelsForDigest`): INSERT INTO notification_deliveries

`ListActiveChannelsForDigest` is defined in `report_channel.go:63`, tested in `report_channel_test.go:120` and `:349`, but **never called from production code**. It is dead code.

**Impact:** The digest runner runs `withOrgTx` (sets `SET LOCAL app.org_id`) instead of `withBypassTx`, violating the architecture convention that workers always use bypass-RLS paths. Functionally, both methods return the same rows (the WHERE clauses are identical) and the runner only uses `ch.ID`, so digests work correctly today. But this means the worker holds org-scoped RLS state in a context where it should be operating with bypass — any future change to the RLS policy or transaction helpers that assumes workers use bypass could break digest channel resolution silently.

---

### 2. PATCH /reports cannot clear severity_threshold back to null

**Location:** `internal/api/reports.go:282-288`
**Severity:** significant
**Evidence:**

The `patchReportBody` uses `*string` for `SeverityThreshold`:

```go
// reports.go:37
type patchReportBody struct {
    SeverityThreshold *string `json:"severity_threshold"`
    // ...
}
```

The handler logic:

```go
// reports.go:282-288
if req.SeverityThreshold != nil {
    if !validSeverityThresholds[*req.SeverityThreshold] {
        http.Error(w, "severity_threshold must be critical, high, medium, or low", http.StatusUnprocessableEntity)
        return
    }
    params.SeverityThreshold = sql.NullString{String: *req.SeverityThreshold, Valid: true}
}
```

- JSON `null` → Go `nil` pointer → skipped (preserves current value, indistinguishable from field-absent)
- JSON `""` → Go `*""` → fails `validSeverityThresholds` check → 422 error
- No code path sets `params.SeverityThreshold = sql.NullString{Valid: false}`

**Impact:** Once a severity threshold is set on a scheduled report, it can never be cleared. The only workaround is to delete and recreate the report. This is asymmetric with `watchlist_ids`, which CAN be cleared by sending `[]` (empty array works because `*[]string` distinguishes nil from empty).

---

### 3. rotateSecretHandler returns empty secret with 200 on TOCTOU race

**Location:** `internal/api/channels.go:419-425`
**Severity:** minor
**Evidence:**

The handler checks channel existence, then calls `RotateSigningSecret`:

```go
// channels.go:404-425
ch, err := srv.store.GetNotificationChannel(r.Context(), orgID, id)
// ... nil check returns 404 ...
if ch.Type != "webhook" { ... }

secret, err := srv.store.RotateSigningSecret(r.Context(), orgID, id)
if err != nil { ... }
writeJSON(w, http.StatusOK, rotateSecretResponse{SigningSecret: secret})
```

`RotateSigningSecret` (notification_channel.go:181-203) returns `("", nil)` when the channel is not found (ErrNoRows treated as nil error). If the channel is soft-deleted between the GET and the rotate, the handler returns:

```json
HTTP 200
{"signing_secret": ""}
```

**Impact:** The client receives an empty signing secret with a success status. Low probability (requires concurrent delete during rotate), but the response is misleading. The handler should check `if secret == ""` and return 404.

---

### 4. Replay rate limit consumed before verifying delivery exists

**Location:** `internal/api/deliveries.go:288-299`
**Severity:** minor
**Evidence:**

```go
// deliveries.go:288-293
if !checkReplayLimit(orgID) {
    http.Error(w, "rate limit exceeded: ...", http.StatusTooManyRequests)
    return
}
if err := srv.store.ReplayDelivery(r.Context(), id, orgID); err != nil { ... }
```

The rate limit counter is incremented (`checkReplayLimit` returns true and bumps `count++` at deliveries.go:51-52) before `ReplayDelivery` executes. `ReplayDelivery` is a SQL no-op for non-existent or non-replayable deliveries (`WHERE status IN ('failed', 'cancelled')`). Both success and no-op return 204.

**Impact:** A client can exhaust their 10-per-hour replay quota by replaying non-existent delivery IDs. Each failed attempt burns a rate limit token. Additionally, the client cannot distinguish "replay succeeded" from "delivery not found" — both return 204.

## Design Concerns

### Replay rate limiter has unbounded memory growth

`deliveries.go:28`: `replayBuckets` is a package-level `sync.Map` keyed by `orgID.String()`. Entries are created by `LoadOrStore` but never evicted. Each bucket is small (~48 bytes), but with many orgs over time, the map grows monotonically. The IP rate limiter (`ipRateLimiter`) and org rate limiter (`orgRateLimiter`) both have eviction goroutines, but `replayBuckets` does not follow this pattern.

### Template block existence not validated at init

`render.go:55-60`: Template files are parsed with `Must` at init, but `Must` only catches parse errors. The `renderPair` function calls `ExecuteTemplate` with named blocks ("subject", "body") — if a template file parses successfully but doesn't define one of these blocks, the error surfaces at runtime during delivery, not at startup. An init-time probe (dry-run execute with zero data) would catch missing block definitions earlier.
