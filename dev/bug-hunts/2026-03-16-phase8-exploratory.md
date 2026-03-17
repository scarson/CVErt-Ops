# Bug Hunt Report — Phase 8 (Operational Maturity) Exploratory

**Date:** 2026-03-16
**Scope:** Phase 8 (PR #15, commit a437c02d). Pillars: 8B Observe, 8C Operate, 8D Extend.
**Methodology:** Depth-first exploratory analysis starting from highest-risk files.

## Scope

Files explored in depth (with reasons):

- `internal/ingest/scheduler.go` — orchestrates feed job scheduling, high impact if broken
- `internal/feed/generic/adapter.go`, `config.go`, `scheduler.go` — brand new external data parsing surface
- `internal/api/feeds.go` — admin feed management handlers, integration point between generic feeds and admin UI
- `internal/api/ingest.go` — inbound webhook, security surface accepting external input
- `internal/api/admin_*.go` — tenant isolation and authorization for admin endpoints
- `internal/api/middleware_auth.go`, `middleware_site_admin.go` — auth enforcement
- `internal/api/auth.go` (login handler) — integration with new disabled/locked/force_password_reset columns
- `internal/store/admin_*.go` — transaction helper correctness
- `internal/store/auth.go` — new `IsSiteAdmin`, `IsUserEnabled` methods
- `internal/api/server.go` — routing/middleware ordering
- `internal/api/metrics_middleware.go` — response code capture correctness
- `internal/notify/worker.go` — delivery worker semaphore eviction
- `internal/doctor/checks.go` — health check implementations
- `migrations/000036-000038` — schema correctness
- `cmd/cvert-ops/main.go` — wiring, generic feed integration

## Bugs

### 1. Scheduler does not respect feed `paused_at` flag

**Location:** `internal/ingest/scheduler.go:126-148`
**Severity:** significant

**Evidence:** The `maybeEnqueue` function checks backoff and interval timing but never reads or checks `state.PausedAt`:

```go
func (s *Scheduler) maybeEnqueue(ctx context.Context, entry FeedScheduleEntry) {
    state, err := s.store.GetFeedSyncState(ctx, entry.FeedName)
    // ...
    if state != nil {
        // Checks backoff — but never checks PausedAt
        if state.BackoffUntil != nil && state.BackoffUntil.After(time.Now()) {
            // ...
            return
        }
        if state.LastSuccessAt != nil && state.LastSuccessAt.Add(entry.Interval).After(time.Now()) {
            // ...
            return
        }
    }
    // Enqueues job even if feed is paused
```

Meanwhile, `store.FeedSyncState` *does* carry `PausedAt` (populated from the DB), and the admin API has `POST /admin/feeds/{feed}/pause` and `POST /admin/feeds/{feed}/resume` endpoints that set/clear `paused_at` in the database. But the scheduler ignores this field entirely.

**Impact:** An admin pauses a feed via the API, but the scheduler continues to enqueue jobs for it. The feed keeps fetching and ingesting data despite being "paused." The pause/resume feature is effectively non-functional for scheduled feeds.

---

### 2. Admin feed endpoints reject generic feed names

**Location:** `internal/api/feeds.go:88`, `internal/api/feeds.go:114`, `internal/api/feeds.go:127`, `internal/api/feeds.go:148`
**Severity:** significant

**Evidence:** All admin feed management endpoints gate on `ingest.IsKnownFeed(feedName)`:

```go
func (srv *Server) triggerFeedHandler(w http.ResponseWriter, r *http.Request) {
    feedName := chi.URLParam(r, "feed")
    if !ingest.IsKnownFeed(feedName) {
        writeProblem(w, http.StatusBadRequest, fmt.Sprintf("unknown feed: %q", feedName))
        return
    }
```

And `ingest.KnownFeeds` is hardcoded:

```go
var KnownFeeds = []string{"nvd", "mitre", "kev", "ghsa", "osv", "epss", "msrc", "redhat"}
```

Generic feed names (loaded from YAML configs in `CVERTOPS_FEEDS_DIR`) are never added to this list. The `listFeedsHandler` also only iterates `ingest.KnownFeeds`, so generic feeds are invisible.

**Impact:** Generic feeds cannot be triggered, paused, resumed, or have their logs viewed via the admin API. The admin feed list doesn't show them at all. This makes generic feeds unmanageable through the admin UI.

---

### 3. Login handler does not check `disabled_at`

**Location:** `internal/api/auth.go:221-308` (loginHandler)
**Severity:** significant

**Evidence:** The login handler retrieves the user via `GetUserByEmail`, verifies the password, and issues tokens — but never checks whether the user is disabled:

```go
func (srv *Server) loginHandler(ctx context.Context, input *loginInput) (*loginOutput, error) {
    // ...
    user, err := srv.store.GetUserByEmail(ctx, input.Body.Email)
    // ... password verification ...
    // Successful login — reset lockout counter.
    srv.lockout.RecordSuccess(input.Body.Email)
    // Issue tokens — no disabled_at check here
    accessToken, err := auth.IssueAccessToken(secret, user.ID, ...)
```

The `RequireAuthenticated` middleware does check `IsUserEnabled` on subsequent requests, but the login itself succeeds. This means:

1. A disabled user can log in and receive valid auth cookies
2. The login response (200 with cookies) reveals that the account exists and the password is correct
3. The tokens are immediately useless (middleware rejects them), but the information leak persists

**Impact:** Information leak for disabled accounts — an attacker can probe whether a disabled account's password is still correct. The admin disables an account expecting immediate lockout, but the user can still "log in" (even though subsequent API calls fail).

---

### 4. Login handler does not check `force_password_reset`

**Location:** `internal/api/auth.go:221-308` (loginHandler)
**Severity:** significant

**Evidence:** Migration 000036 adds `force_password_reset boolean NOT NULL DEFAULT false` to the users table, and the admin API has `POST /admin/users/{user_id}/reset-password` that sets this flag. But the login handler never reads or checks it. A search for `force_password_reset` in `internal/api/auth.go` returns no results.

**Impact:** The `force_password_reset` admin feature is a no-op. An admin forces a password reset on a user, but the user can continue logging in with their existing password indefinitely. The flag is set in the database but never enforced.

---

### 5. Lockout state is not persisted to database `locked_at`/`failed_login_count` columns

**Location:** `internal/api/lockout.go` (entire file), `internal/api/auth.go:233-283`
**Severity:** minor

**Evidence:** Migration 000036 adds `locked_at timestamptz` and `failed_login_count int` columns to the users table. The admin API has `POST /admin/users/{user_id}/unlock` that clears these columns. But the login flow's `lockoutManager` is purely in-memory:

```go
type lockoutManager struct {
    mu        sync.Mutex
    attempts  map[string]*loginAttempt  // in-memory only
    threshold int
    duration  time.Duration
    // ...
}
```

The `lockoutManager` never reads from or writes to the database `locked_at`/`failed_login_count` columns. The admin "unlock user" endpoint clears DB columns that are never set by the login flow.

**Impact:** (1) Lockout state is lost on server restart — a brute-force attack can simply wait for a deploy. (2) In multi-instance deployments, lockout state is per-instance — an attacker can distribute attempts across instances. (3) The admin "unlock user" button is ineffective — it clears DB columns the login flow never writes, while the in-memory lockout (which the admin can't clear) is the actual enforcement mechanism.

---

### 6. Admin `PATCH /orgs/{org_id}` applies tier and suspend in separate transactions

**Location:** `internal/api/admin_orgs.go:122-157`
**Severity:** minor

**Evidence:** When both `tier` and `suspend` are sent in the same PATCH request, they execute as separate store calls (each with its own `withBypassTx`):

```go
if body.Tier != nil {
    // ...
    if _, err := srv.store.AdminUpdateOrgTier(r.Context(), orgID, *body.Tier); err != nil {
        // error handling
    }
}

if body.Suspend != nil {
    if *body.Suspend {
        if _, err := srv.store.AdminSuspendOrg(r.Context(), orgID); err != nil {
            // error handling
        }
    }
    // ...
}
```

**Impact:** If the tier update succeeds but the suspend fails, the org is left in a partially-updated state (new tier but not suspended). The admin would need to retry the suspend manually. The response returns the re-fetched org, which would show the partial state, so the admin would at least see the inconsistency — but it violates PATCH atomicity expectations.

---

## Design Concerns

### Generic feed / built-in feed integration gap

The generic feed system and the built-in feed system were developed as separate tracks that converge at two points: the adapter factory (working correctly) and the scheduler entries (working correctly). But the admin management layer (`listFeedsHandler`, `triggerFeedHandler`, `pauseFeedHandler`, `resumeFeedHandler`, and `IsKnownFeed` validation) was not extended to accommodate generic feeds. This creates a blind spot where generic feeds run but are invisible and unmanageable through the admin interface.

The fix likely involves either:
- Passing the list of loaded generic feed names to the server (so it can include them in the feed list and accept them in trigger/pause/resume), or
- Changing the feed list handler to enumerate `feed_sync_state` rows directly rather than iterating a hardcoded list

### Login handler needs to integrate with Phase 8 user management columns

The `disabled_at`, `locked_at`, `failed_login_count`, and `force_password_reset` columns were added in migration 000036 and are managed by the admin API, but the login handler was not updated to check any of them. The auth middleware partially compensates for `disabled_at` (checking it on token validation), but `force_password_reset` has no enforcement anywhere in the request lifecycle.

### Scheduler-to-admin-API contract for feed pausing

The pause/resume endpoints write `paused_at` to `feed_sync_state`, but the scheduler — the only component that auto-enqueues feed jobs — never reads this field. The manual trigger endpoint (`triggerFeedHandler`) also doesn't check `paused_at`, so even manual triggers ignore the pause state. The pause feature needs enforcement at the scheduling and triggering layers, not just the persistence layer.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| Significant | 4 |
| Minor | 2 |
| **Total** | **6** |
