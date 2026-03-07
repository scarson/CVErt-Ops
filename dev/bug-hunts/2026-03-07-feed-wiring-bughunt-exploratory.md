# Bug Hunt Report — Feed Wiring (Exploratory)

**Date:** 2026-03-07
**Branch:** feed-wiring (vs main)
**Method:** Depth-first exploratory analysis, starting from highest-risk entry points

## Scope

**Deep exploration:**
- `internal/ingest/handler.go` — feed ingest handler (pagination, cursor, error recovery)
- `internal/ingest/epss.go` — EPSS handler (sync state tracking)
- `internal/ingest/scheduler.go` — feed scheduler (timing, dedup, enqueue)
- `internal/ingest/feeds.go` — adapter factory, feed name registry
- `internal/api/feeds.go` — admin feed status + manual trigger endpoints
- `internal/store/feed.go` — feed sync state and fetch log store methods
- `internal/store/jobs.go` — `HasPendingOrRunningJob` + `EnqueueJob` store methods
- `internal/store/queries/feed.sql` — `InsertFeedFetchLog` SQL definition
- `internal/feed/epss/adapter.go` — EPSS two-statement pattern, advisory locks
- `internal/merge/pipeline.go` — merge pipeline integration (advisory locks, EPSS staging)
- `internal/merge/resolve.go` — field resolution, URL canonicalization, reference handling

**Reviewed for patterns:**
- `internal/feed/nvd/adapter.go` — NVD streaming parse, cursor/pagination
- `internal/feed/ghsa/adapter.go` — GHSA streaming parse, link header pagination
- `internal/feed/osv/adapter.go` — OSV ZIP parse, alias resolution
- `internal/feed/mitre/adapter.go` — MITRE ZIP parse
- `internal/feed/kev/adapter.go` — KEV streaming parse, version short-circuit
- `internal/feed/msrc/adapter.go` — MSRC two-phase fetch, CSAF parse
- `internal/feed/redhat/adapter.go` — Red Hat two-phase fetch, polymorphic JSON
- `internal/feed/util.go` — shared utilities (ParseTime, DownloadToTemp, ResolveCanonicalID)
- `internal/feed/interface.go` — Adapter interface, FetchResult, CanonicalPatch types

## Bugs

### 1. InsertFeedFetchLog silently drops started_at and ended_at — fetch duration is always zero

**Location:** `internal/store/queries/feed.sql:18-24` (SQL definition), `internal/store/feed.go:76-95` (store method)
**Severity:** significant

**Evidence:** The `InsertFeedFetchLog` SQL inserts only these columns:
```sql
INSERT INTO feed_fetch_log (
    feed_name, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary, ended_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
```

- `started_at` is NOT in the INSERT column list — it falls back to a `DEFAULT now()` (table default).
- `ended_at` is hardcoded to `now()` in the SQL, ignoring the caller's value.

Both columns get the same `now()` value (the DB transaction timestamp). Meanwhile, the caller (handler.go:35-36, handler.go:136-146) carefully tracks `start := time.Now()` and `now := time.Now()` to compute the actual duration, and passes them as `StartedAt: start` and `EndedAt: &now` in the `FeedFetchLog` struct — but the store method never maps `StartedAt` or `EndedAt` to the generated params because the SQL doesn't accept them.

The `InsertFeedFetchLogParams` struct confirms: no `StartedAt` or `EndedAt` field.

**Impact:** Every feed fetch log entry has `started_at == ended_at == INSERT time`. Operators cannot determine actual fetch duration from the log. For feeds like NVD (multi-hour backfills) or OSV/MITRE (large ZIP downloads), this makes performance debugging impossible. The `FeedFetchLog.StartedAt` and `FeedFetchLog.EndedAt` fields on the domain struct are misleading — they suggest the data is persisted when it isn't.

### 2. Silently discarded UpsertFeedSyncState errors can cause cursor loss

**Location:** `internal/ingest/handler.go:127`, `internal/ingest/handler.go:157`, `internal/ingest/epss.go:50`, `internal/ingest/epss.go:73`
**Severity:** significant

**Evidence:** All sync state writes use `_ = st.UpsertFeedSyncState(...)`. Four instances:

**Success path (handler.go:157):** If `UpsertFeedSyncState` fails after all patches are merged, the cursor and success state are lost. Next scheduler tick sees no `LastSuccessAt` or an old cursor → re-fetches everything. For NVD (120-day windows, 2000-item pages), this could re-merge tens of thousands of patches unnecessarily. The handler returns `nil` (success) to the worker, so the job is marked complete and never retried.

**Error path (handler.go:127):** If `UpsertFeedSyncState` fails, backoff state isn't recorded. The scheduler won't see `BackoffUntil` → immediately re-schedules the feed → hammers the upstream API that just rejected us. The `ConsecutiveFailures` counter also won't increment, so backoff never escalates.

**EPSS paths (epss.go:50, 73):** Same patterns as handler.go.

**Impact:** Transient DB errors during sync state writes cause: (a) redundant full re-fetches on success path, (b) unbounded retry storms on error path. Both are silent — no log, no error propagation, no indication that state was lost.

### 3. TOCTOU race in job deduplication allows duplicate feed jobs

**Location:** `internal/ingest/scheduler.go:101-116` (scheduler), `internal/api/feeds.go:80-94` (trigger handler)
**Severity:** minor

**Evidence:** Both the scheduler and the trigger handler follow the same check-then-insert pattern:

```go
// scheduler.go:101-113
lockKey := "feed:" + entry.FeedName
has, err := s.store.HasPendingOrRunningJob(ctx, lockKey)
// ... error handling ...
if has { return }
s.store.EnqueueJob(ctx, entry.Queue, 0, payload, &lockKey, 3, nil)
```

`HasPendingOrRunningJob` runs in its own `withBypassTx` transaction (store/jobs.go:116-120). `EnqueueJob` runs as a standalone query on `s.q` (store/jobs.go:99-106). Between the check and the insert, another goroutine (concurrent scheduler tick, API trigger, or the scheduler + trigger racing each other) can also see no pending job and enqueue a duplicate.

There is no UNIQUE constraint on `lock_key` in `job_queue` and no `ON CONFLICT` clause on `EnqueueJob`. Duplicates will be inserted and both executed.

**Impact:** Two concurrent feed ingest workers run for the same feed. Wasted compute and API quota but no data corruption — the merge pipeline is idempotent. More concerning for rate-limited feeds like NVD where duplicate fetches could trigger upstream rate limiting (429 errors).

### 4. Streaming JSON `continue` after Decode error corrupts decoder state

**Location:** `internal/feed/nvd/adapter.go:394-397`, `internal/feed/ghsa/adapter.go:205-207`
**Severity:** minor

**Evidence:** Both NVD and GHSA adapters skip malformed records with `continue` after a `json.Decoder.Decode()` error:

```go
// nvd/adapter.go:393-397
for dec.More() {
    var wrapper nvdVulnWrapper
    if err := dec.Decode(&wrapper); err != nil {
        continue  // Skip malformed records; do not abort the page.
    }
```

Per Go stdlib documentation, after `Decode` returns an error, the decoder's internal state is undefined. Subsequent calls to `More()` and `Decode()` may:
- Skip valid records that immediately follow the malformed one
- Return partial/garbled data from the next record
- Panic on unexpected token state

**Impact:** In practice this is low-risk because: (a) NVD responses are well-formed JSON (NIST validates), (b) skipped records are re-ingested on the next run, (c) the merge pipeline is idempotent. But if a legitimate parse error occurs mid-stream, valid records after the error may be silently dropped with no indication. This is a correctness concern, not a data corruption risk.

### 5. backoffDuration panics on negative consecutive_failures from corrupt DB data

**Location:** `internal/ingest/handler.go:187-190`
**Severity:** minor

**Evidence:**
```go
func backoffDuration(failures int32) time.Duration {
    base := 30 * time.Second
    return base * time.Duration(1<<min(failures, 10))
}
```

If `failures` (from `prevFailures + 1`, where `prevFailures` is read from DB column `consecutive_failures`) is negative due to data corruption, `min(failures, 10)` returns a negative int32. `1 << negativeValue` causes a Go runtime panic — the shift count must be non-negative.

**Impact:** Extremely unlikely — `consecutive_failures` is only set by the handler via `prevFailures + 1` starting from 0. Would require manual DB corruption. But the function doesn't defend against it, and a panic in a worker goroutine could crash the process.

## Design Concerns

### Sync state and fetch log writes share no transaction with the actual work

The handler (handler.go:66-118) runs a pagination loop that merges patches one at a time via `mergeFn()`, each in its own advisory-locked transaction. After the loop, sync state and fetch log are written in separate `withBypassTx` transactions. A crash between the last merge and the sync state write loses the cursor — the entire feed is re-processed.

This is architecturally intentional (per-row advisory locks cannot span the entire handler), but the discarded-error pattern (Bug #2) compounds the risk: even a transient DB error at the sync-state write stage causes the same full-re-process behavior as a crash, silently.

### No size limit on DownloadToTemp disk writes

`feed.DownloadToTemp()` (util.go:135-170) streams an entire HTTP response to a temp file with `io.Copy(f, resp.Body)` and no size cap. For MITRE (~300 MB) and OSV (~2 GB), this is expected. But if an upstream server returns an unexpectedly large response (e.g., HTTP 200 with infinite body from a CDN misconfiguration), the write continues until the disk is full. Individual adapter Fetch methods apply `LimitReader` to in-memory reads but `DownloadToTemp` has no equivalent.

### GHSA/MSRC/Red Hat internal pagination defeats handler-level cursor recovery

GHSA, MSRC, and Red Hat adapters fetch all pages internally within a single `Fetch()` call and return `LastPage: true`. If an internal request fails on page 5 of 10, all work from pages 1-4 is discarded — the handler saves the original cursor and retries from scratch. For GHSA backfills (5,000+ advisories across many pages), this can be significantly wasteful. NVD avoids this by returning one page per `Fetch()` call, allowing the handler to persist cursor progress per page.