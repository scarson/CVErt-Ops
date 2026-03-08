# Bug Hunt Report — Feed Wiring (Holistic)

**Date:** 2026-03-07
**Branch:** feed-wiring
**Method:** Holistic — read all source files, reasoned globally about cross-cutting interactions

## Scope

Analyzed the feed-wiring branch changes: `internal/ingest/` (handler, scheduler, feeds, epss), `internal/store/feed.go`, `internal/store/jobs.go`, `internal/api/feeds.go`, `internal/feed/interface.go`, `internal/feed/util.go`, `internal/feed/epss/adapter.go`, `internal/merge/pipeline.go`, `internal/worker/pool.go`, `internal/worker/job.go`, `internal/api/server.go`, `cmd/cvert-ops/main.go`, `web/src/views/FeedStatusView.vue`, `web/src/lib/api/orgFetch.ts`, SQL queries (`feed.sql`, `jobs.sql`), generated sqlc code, and migration `000003_create_feed_state.up.sql`.

Focus: cross-package interactions between the ingest handler, scheduler, merge pipeline, EPSS adapter, admin API, worker pool, and Vue dashboard.

## Bugs

### 1. `expectedSchemaVersion` is stale — startup always warns

**Location:** [cmd/cvert-ops/main.go:529](cmd/cvert-ops/main.go#L529)
**Severity:** significant
**Evidence:** `const expectedSchemaVersion = 24` but the latest migration is `000029_vendor_enrichment`. After running `cvert-ops migrate`, the advisory check on lines 501–509 compares `schemaVersion` (29) against `expectedSchemaVersion` (24) and always emits a warning:
```
schema version mismatch — run `cvert-ops migrate` (applied_version=29, expected_version=24)
```
This warning fires on every startup even when the schema is up to date, making it useless as a diagnostic signal.
**Impact:** Operators see a permanent misleading warning. If they trust it, they waste time re-running migrations that are already applied. If they learn to ignore it, real schema mismatches go undetected.

### 2. `InsertFeedFetchLog` discards the actual start time

**Location:** [internal/store/queries/feed.sql:19-24](internal/store/queries/feed.sql#L19-L24)
**Severity:** significant
**Evidence:** The `InsertFeedFetchLog` SQL does not include `started_at` in its column list:
```sql
INSERT INTO feed_fetch_log (
    feed_name, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary, ended_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
```
The `started_at` column defaults to `now()` (migration line 44). The ingest handler captures the real start time (`start := time.Now()` at [handler.go:35](internal/ingest/handler.go#L35)) and stores it in the `FeedFetchLog` struct, but the SQL never receives it. The `started_at` in the DB reflects when the log was written (end of fetch), not when the fetch began.

For a long-running NVD paginated fetch that takes 5+ minutes, both `started_at` and `ended_at` will show approximately the same time (the end), making the fetch log useless for diagnosing performance issues. The same issue affects EPSS handler logs ([epss.go:59](internal/ingest/epss.go#L59), [epss.go:81](internal/ingest/epss.go#L81)).
**Impact:** Feed fetch logs show incorrect duration data. Debugging slow feeds becomes impossible from the fetch log alone.

### 3. Sync state persistence errors silently swallowed

**Location:** [internal/ingest/handler.go:127](internal/ingest/handler.go#L127), [handler.go:157](internal/ingest/handler.go#L157), [epss.go:50](internal/ingest/epss.go#L50), [epss.go:73](internal/ingest/epss.go#L73)
**Severity:** significant
**Evidence:** Both the feed handler and EPSS handler discard errors from `UpsertFeedSyncState`:
```go
_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{...})  // handler.go:127, 157
_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{...})  // epss.go:50, 73
```

On the **success path** (handler.go:157): if the cursor upsert fails, the job completes successfully but the cursor isn't advanced. The next scheduler tick sees the old `LastSuccessAt`, schedules a new run, and the adapter re-fetches all the same data from the old cursor position. For NVD with a 120-day window, this means re-processing thousands of CVEs unnecessarily.

On the **error path** (handler.go:127): if the backoff/failure state upsert fails, the scheduler doesn't know the feed is in backoff. It re-enqueues the job on the next tick (1 minute), potentially hammering a rate-limited upstream API.

Both `InsertFeedFetchLog` errors are also silently swallowed (handler.go:136, 165; epss.go:59, 81).
**Impact:** Silent re-fetch of entire feed windows on transient DB errors. Potential upstream rate-limit violations when backoff state isn't persisted. No observability into sync state write failures.

### 4. Admin feed endpoints lack role-based authorization

**Location:** [internal/api/server.go:196-200](internal/api/server.go#L196-L200)
**Severity:** significant
**Evidence:** The admin feed routes only require `RequireAuthenticated()`:
```go
apiRouter.Route("/admin", func(r chi.Router) {
    r.Use(srv.RequireAuthenticated())
    r.Get("/feeds", srv.listFeedsHandler)
    r.Post("/feeds/{feed}/run", srv.triggerFeedHandler)
})
```
Any authenticated user — including a viewer-role member of any org — can list all feed sync states (potentially revealing internal infrastructure details) and trigger manual feed runs (a privileged operation that consumes upstream API quota and server resources).

The trigger endpoint is particularly concerning: an unprivileged user can force all 8 feeds to re-run simultaneously, exhausting rate limits and potentially blocking legitimate scheduled syncs for hours.
**Impact:** Authorization bypass for administrative operations. Any authenticated user can trigger arbitrary feed runs.

### 5. Scheduler-to-trigger deduplication race (TOCTOU)

**Location:** [internal/ingest/scheduler.go:101-113](internal/ingest/scheduler.go#L101-L113), [internal/api/feeds.go:80-94](internal/api/feeds.go#L80-L94)
**Severity:** minor
**Evidence:** Both the scheduler and the admin trigger handler use the same deduplication pattern:
```go
has, err := s.store.HasPendingOrRunningJob(ctx, lockKey)
// ... gap where another goroutine can enqueue ...
s.store.EnqueueJob(ctx, ...)
```
There is no database-level uniqueness constraint on `(lock_key, status)` for pending jobs. The `job_queue_lock_key_running_uq` unique index only covers `status = 'running'`, not `status = 'pending'`. If the scheduler tick and an admin trigger race, two pending jobs for the same feed can be enqueued.

The running-uniqueness constraint prevents concurrent *execution*, and the merge pipeline is idempotent, so the second run wastes resources but doesn't corrupt data.
**Impact:** Under race conditions, a feed fetch may execute twice sequentially, doubling API calls and merge work for that cycle.

## Design Concerns

### Silent error suppression as a pattern

The `_ = st.UpsertFeedSyncState(...)` and `_, _ = st.InsertFeedFetchLog(...)` pattern is used 8 times across the ingest handlers. While the intent is "don't fail the job over a logging failure," the blanket suppression means there's zero observability into sync state failures. Even a `slog.Error` call on these paths would make debugging possible without changing the control flow. The current pattern means a persistent DB issue (e.g., connection pool exhaustion) would manifest as mysterious re-fetches rather than clear error messages.

### Scheduler does not emit metrics

The scheduler silently enqueues or skips feeds with only debug-level logging. There are no Prometheus counters for feeds_scheduled, feeds_skipped_backoff, or feeds_skipped_not_due. In production, operators have no visibility into whether the scheduler is working correctly without enabling debug logging.

### Admin API returns empty list for unconfigured feeds

`ListFeedSyncStates` returns only feeds that have existing `feed_sync_state` rows. On first boot (before any feed has run), the admin API returns `{"feeds": []}` and the Vue dashboard shows "No feed data yet." The `ingest.KnownFeeds` list defines 8 feeds, but none appear in the dashboard until the scheduler has run at least once. Consider seeding initial rows or joining against `KnownFeeds` to show all feeds with "Never Synced" status from the start.