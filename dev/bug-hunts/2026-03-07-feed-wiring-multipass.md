# Bug Hunt Report — Feed Hardening Multi-Pass

**Date:** 2026-03-07
**Hunter:** Claude (code-bug-hunter-multipass)
**Branch:** feed-wiring

## Scope

17 source files analyzed across 6 packages:

- `internal/feed/` — interface.go, util.go, epss/adapter.go, ghsa/adapter.go, nvd/adapter.go, kev/adapter.go, mitre/adapter.go, osv/adapter.go, msrc/adapter.go, redhat/adapter.go
- `internal/ingest/` — handler.go, epss.go, scheduler.go, feeds.go
- `internal/api/` — feeds.go, middleware_site_admin.go
- `internal/merge/` — pipeline.go
- `internal/store/` — feed.go, jobs.go

Five passes performed: Contract Violations, Cross-Sibling Pattern Violations, Failure Mode Reasoning, Concurrency Reasoning, Error Propagation.

---

## Bugs

### 1. Mid-page cursor persist resets failure tracking on crash

**Location:** internal/ingest/handler.go:122-130
**Severity:** significant
**Found in:** Pass 1 — Contract Violations / Pass 3 — Failure Mode Reasoning

**Evidence:** The mid-pagination cursor persist writes a `FeedSyncState` struct literal with zero-value fields:

```go
if syncErr := syncSt.UpsertFeedSyncState(ctx, store.FeedSyncState{
    FeedName:      p.FeedName,
    CursorJSON:    lastSuccessfulCursor,
    LastSuccessAt: prevLastSuccess,
    LastAttemptAt: &pageNow,
    // ConsecutiveFailures: 0      (int32 zero value)
    // LastError:           ""     (string zero value)
    // BackoffUntil:        nil    (pointer zero value)
}); syncErr != nil {
```

`UpsertFeedSyncState` writes ALL columns, including `ConsecutiveFailures=0`, `LastError=NULL`, and `BackoffUntil=NULL`. This overwrites any existing failure/backoff state in the database.

In the *normal* error flow (no crash), `prevFailures` was captured at handler start (line 68) and the error path (line 151) computes `prevFailures + 1`, so escalation works correctly — the mid-page write is overwritten by the error-path write.

**Impact:** On **process crash** between a mid-page persist and the error-path persist, the database retains `ConsecutiveFailures=0` and `BackoffUntil=NULL`. On restart:
1. Scheduler sees no backoff, immediately re-enqueues the feed
2. Handler reads `ConsecutiveFailures=0` from DB
3. If the same page fails again, `failures = 0 + 1 = 1` — backoff is only 60s instead of the accumulated backoff
4. Failure history is permanently lost; the exponential backoff never reaches protective levels

Scenario: Feed has 5 consecutive failures (backoff ~16 min) → backoff expires → run starts → page 1 succeeds → mid-page persist resets CF=0 → process crashes → on restart, backoff is gone, and if page 2 keeps failing, CF oscillates near 1 instead of escalating to 6, 7, 8...

**Fix:** Either:
- (a) Carry `prevFailures` into the mid-page persist: `ConsecutiveFailures: prevFailures`
- (b) Only write cursor/timing fields in the mid-page persist, leaving failure-tracking columns untouched (requires a separate SQL statement or a partial-update store method)

---

### 2. NewSchedulerWithRegistry mutates package-level Prometheus vars without synchronization

**Location:** internal/ingest/scheduler.go:67-75
**Severity:** minor
**Found in:** Pass 4 — Concurrency Reasoning

**Evidence:** `NewSchedulerWithRegistry` replaces the package-level `feedJobsEnqueued` and `feedJobsSkipped` counter vecs:

```go
func NewSchedulerWithRegistry(st SchedulerStore, reg prometheus.Registerer) *Scheduler {
    feedJobsEnqueued = promauto.With(reg).NewCounterVec(...)  // writes to package var
    feedJobsSkipped = promauto.With(reg).NewCounterVec(...)   // writes to package var
    ...
}
```

These are unguarded writes to package-level variables that are concurrently read by `maybeEnqueue` (lines 117, 124, 139, 143). If two goroutines call `NewSchedulerWithRegistry` concurrently (e.g., parallel tests), or if a scheduler tick fires while `NewSchedulerWithRegistry` is executing, the counter vec pointers can be read in a torn state.

**Impact:** In production, `NewSchedulerWithRegistry` is only called at startup before the scheduler goroutine begins, so no race occurs. The risk is in tests with `t.Parallel()` — two tests creating schedulers with different registries can race. Since this function is specifically for testing, the race is more likely to manifest than one might expect.

**Fix:** Store the counter vecs on the `Scheduler` struct instead of mutating package-level vars. Each scheduler instance gets its own metrics, and the package-level vars remain as the default (registered on the global registry).

---

## Design Concerns

### Package-level var overrides for testability are not concurrency-safe

`applyRowFn` (epss/adapter.go:233) and `adapterFactory` (ingest/feeds.go:43) are package-level vars designed for test injection. Neither is protected by a mutex. Tests that override these vars and run with `t.Parallel()` will race. This is a widespread pattern in the codebase; consider using struct-field injection instead, or at minimum ensure these tests are not parallelized.

### EPSS rate limiter can block a worker goroutine for up to 24 hours

The EPSS adapter's rate limiter is configured as `rate.Every(24*time.Hour)` with burst=1 (epss/adapter.go:91). If the cursor-based daily skip (line 116-124) fails (e.g., corrupted cursor JSON), and Apply is called twice within 24 hours, the second `rateLimiter.Wait(ctx)` blocks for up to 24 hours. Since worker goroutines typically don't have a per-job timeout, this silently ties up a worker slot. In normal operation the daily cursor check prevents this, but a corrupt cursor could trigger it. Consider using `rateLimiter.WaitN` with a timeout-wrapped context, or using a shorter rate limit as a safety net and relying on the scheduler interval for the 24-hour cadence.

### NVD final page returns nil NextCursor, causing last-window re-processing

When NVD's `computeNextCursor` returns nil (all windows exhausted), the handler does not update `lastSuccessfulCursor` (handler.go:115-116 — the update is conditional on `NextCursor != nil`). The persisted cursor points to the start of the last-processed window, causing the next scheduled run to re-query that window. The overlap mechanism and IS DISTINCT FROM guards make this idempotent, but it's unnecessary I/O. The re-processing is typically small (a single window near the current time), so the impact is low.

---

## Passes with no bugs found

### Pass 2: Cross-Sibling Pattern Violations

All 7 feed adapters correctly implement `feed.Adapter`. Patterns checked:

- **Streaming parse:** NVD, GHSA, KEV use `json.Decoder` Token()/More() loops. MITRE and OSV parse individual small files from ZIP archives (no streaming needed). MSRC and Red Hat parse bounded responses (capped at 5-50 MB). No violations of the streaming parse requirement for large feeds.
- **Rate limiters:** All adapters create and manage their own `rate.Limiter` in `New()`, with appropriate rates for each upstream API. All call `rateLimiter.Wait(ctx)` before HTTP requests, including within pagination loops (MSRC Phase 2, Red Hat Phase 2).
- **Lock key format:** Scheduler (scheduler.go:131) and trigger endpoint (api/feeds.go:92) both use `"feed:" + feedName`. Consistent.
- **Cursor persistence:** All single-page adapters (KEV, MITRE, OSV, MSRC) return non-nil `NextCursor` with `LastPage: true`. All paginators (NVD, GHSA, Red Hat) return non-nil `NextCursor` with `LastPage: false` on intermediate pages and `LastPage: true` on the final page (NVD uses nil NextCursor as an alternative termination signal).
- **Null byte stripping:** All adapters consistently apply `feed.StripNullBytes()` and `strings.Clone()` to all string fields extracted from upstream JSON.

### Pass 5: Error Propagation

All error paths correctly handled:

- **EPSS handler** (epss.go:81): Returns `applyErr` (the original error) even when sync state or fetch log writes fail. Sync/log write errors are logged but do not mask the original error.
- **Feed handler error path** (handler.go:185): Returns `fetchErr` (the original error). Sync state and fetch log write failures on the error path are logged but do not prevent the original error from being returned to the worker pool.
- **Feed handler success path** (handler.go:199): Sync state write failure on success IS returned as an error (the patches were already merged, so the worker will retry, re-merging idempotently via IS DISTINCT FROM guards). Fetch log write failure on success is logged but not returned (best-effort).
- **EPSS adapter per-row errors** (epss/adapter.go:217-221): Individual row DB errors are logged as warnings and skipped. The adapter continues processing remaining rows. The full cursor is returned on success, so skipped rows will be retried on the next run (scores are re-downloaded daily). This is intentional — one row failure should not abort 250k row processing.
