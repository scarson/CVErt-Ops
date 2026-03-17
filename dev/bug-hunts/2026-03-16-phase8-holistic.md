# Bug Hunt Report — Phase 8 (Operational Maturity)

## Scope

Packages/files analyzed — all Phase 8 source files (non-test):

**Go backend:**
- `cmd/cvert-ops/main.go`, `doctor.go`, `validate.go`
- `internal/api/server.go`, `feeds.go`, `ingest.go`, `admin_deliveries.go`, `admin_doctor.go`, `admin_orgs.go`, `admin_system.go`, `admin_users.go`, `admin_version.go`, `readyz.go`, `log_middleware.go`, `metrics_middleware.go`, `middleware_auth.go`, `middleware_site_admin.go`, `org_ratelimit.go`
- `internal/config/config.go`
- `internal/doctor/doctor.go`, `checks.go`
- `internal/feed/generic/adapter.go`, `config.go`, `scheduler.go`
- `internal/ingest/handler.go`, `scheduler.go`
- `internal/log/context.go`
- `internal/metrics/alert.go`, `db.go`, `feed.go`, `http.go`, `notification.go`, `worker.go`
- `internal/notify/worker.go`
- `internal/worker/pool.go`
- `internal/store/store.go`, `admin_delivery.go`, `admin_org.go`, `admin_system.go`, `admin_user.go`, `audit.go`, `auth.go`, `feed.go`
- SQL: `admin_deliveries.sql`, `admin_orgs.sql`, `admin_system.sql`, `admin_users.sql`, `auth.sql`, `feed.sql`
- Migrations: `000036`, `000037`, `000038`

**Vue frontend:**
- `AdminDashboardView.vue`, `AdminFeedsView.vue`, `AdminAuditLogView.vue`, `AdminDeliveriesView.vue`, `AdminOrgsView.vue`, `AdminUsersView.vue`, `AdminSystemView.vue`

**Approach:** Read all source files into context, then analyzed for contract violations, pattern deviations, failure modes, and cross-component consistency issues.

## Bugs

### 1. Scheduler ignores paused feeds — paused feeds continue to run

**Location:** `internal/ingest/scheduler.go:126-164`
**Severity:** significant

**Evidence:** The `maybeEnqueue` function checks for backoff (line 135) and not-yet-due (line 142), but never checks `state.PausedAt`. The admin API correctly sets `paused_at` via `PauseFeed`/`ResumeFeed` store methods, and the frontend correctly displays paused status and offers resume controls, but the scheduler completely ignores the flag.

```go
// Line 133-148: checks backoff and not-due, but no PausedAt check
if state != nil {
    if state.BackoffUntil != nil && state.BackoffUntil.After(time.Now()) {
        // ... skip backoff
        return
    }
    if state.LastSuccessAt != nil && state.LastSuccessAt.Add(entry.Interval).After(time.Now()) {
        // ... skip not-due
        return
    }
    // BUG: No check for state.PausedAt here
}
// Falls through to enqueue the job
```

Additionally, `internal/ingest/handler.go` (the worker handler that executes feed jobs) also does not check pause state before running, so even a manually triggered feed run via the admin API would execute for a paused feed (though this is arguably by design for the manual trigger — the scheduler bypass is clearly a bug).

**Impact:** An admin pauses a misbehaving feed via the UI, but it continues to be scheduled and executed on its normal interval. The pause/resume feature is completely non-functional. This is particularly dangerous for feeds that are paused because they're causing upstream rate limit violations or processing errors.

### 2. Doctor health check results silently discarded when system is unhealthy

**Location:** `web/src/views/admin/AdminSystemView.vue:54` and `web/src/views/admin/AdminSystemView.vue:76`
**Severity:** significant

**Evidence:** The code correctly identifies that the typed openapi-fetch client cannot handle 503 responses (comment on lines 44-46) and falls back to raw `fetch`. However, both `fetchAll()` and `runDoctor()` check `resp.ok`, which is `false` for status codes outside 200-299. The doctor endpoint returns 503 with a valid JSON body when the system is unhealthy (`internal/api/admin_doctor.go:29`).

```typescript
// Line 54 — fetchAll:
if (doctorResp.ok) {  // false for 503
  doctor.value = (await doctorResp.json()) as DoctorResult
}

// Line 76 — runDoctor:
if (resp.ok) {  // false for 503
  doctor.value = (await resp.json()) as DoctorResult
}
```

The fix is to check `resp.status === 200 || resp.status === 503` (or simply check `resp.headers.get('content-type')` includes JSON, then always parse the body).

**Impact:** The doctor health check card only displays results when the system is healthy. When the system is unhealthy (the exact moment the admin needs this information most), the card either shows nothing (initial load) or retains stale data (re-run). This defeats the purpose of the health check feature entirely.

## Design Concerns

### Admin manual feed trigger runs paused feeds

The `triggerFeedHandler` in `internal/api/feeds.go:84-108` does not check whether a feed is paused before enqueueing a manual run. This is defensible as a design choice (admin override), but it's worth noting that nothing in the UI indicates this behavior — the "Run" button appears alongside the "Resume" button for paused feeds, which could be confusing. If the intent is that manual triggers should respect pause state, this is a second instance of the paused-feed bypass bug.

### Raw `fetch` bypasses typed client interceptors

`AdminSystemView.vue` uses raw `fetch('/api/v1/admin/doctor', { credentials: 'include' })` instead of the typed openapi-fetch client. While the comment explains why (503 handling), this bypasses any request/response interceptors the typed client has (e.g., token refresh on 401). If the JWT expires while the admin is on this page and they click "Run" on the doctor check, the raw fetch would get a 401 without automatic refresh. This is a minor ergonomic issue rather than a correctness bug since the other two API calls on the page use the typed client and would trigger refresh.

### Scheduler `AddEntries` not concurrency-safe

`internal/ingest/scheduler.go:96-98` — `AddEntries` appends to the `schedule` slice with no synchronization. The comment says "Must be called before Start," and current usage in `main.go` respects this. However, the lack of a mutex or documentation-enforced lifecycle makes this fragile if future callers add entries after start.
