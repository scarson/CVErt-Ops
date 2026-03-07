# Bug Hunt Report — Feed Wiring Exploratory

**Date:** 2026-03-07
**Scope:** Feed adapter standardization, ingest handler, EPSS hardening, scheduler, admin API
**Method:** Depth-first exploratory analysis starting from highest-risk files

## Scope

### Files explored deeply
- `internal/feed/epss/adapter.go` — EPSS CSV download, advisory-locked per-row DB writes, poison row skip
- `internal/ingest/handler.go` — pagination loop, cursor persistence, three-layer termination
- `internal/ingest/epss.go` — EPSS handler wrapping Apply with sync state tracking
- `internal/ingest/scheduler.go` — feed scheduling with backoff, dedup, Prometheus metrics
- `internal/ingest/feeds.go` — adapter factory, KnownFeeds registry
- `internal/merge/pipeline.go` — CVE merge pipeline with advisory locking, PK migration
- `internal/merge/resolve.go` — per-field source precedence resolution
- `internal/merge/hash.go` — material hash computation
- `internal/store/feed.go` — feed sync state + fetch log store methods
- `internal/store/jobs.go` — job queue store methods
- `internal/feed/interface.go` — FeedAdapter interface, FetchResult, SourceMeta
- `internal/feed/util.go` — shared feed utilities
- `internal/api/feeds.go` — admin feed status + manual trigger endpoints
- `internal/api/middleware_site_admin.go` — site admin authorization middleware

### Feed adapters examined
- `internal/feed/nvd/adapter.go` — NVD paginated adapter (deep read, traced cursor lifecycle)
- `internal/feed/ghsa/adapter.go` — GHSA streaming JSON adapter
- `internal/feed/kev/adapter.go` — KEV single-file adapter
- `internal/feed/mitre/adapter.go` — MITRE ZIP adapter
- `internal/feed/osv/adapter.go` — OSV bulk ZIP adapter
- `internal/feed/msrc/adapter.go` — MSRC CSAF adapter
- `internal/feed/redhat/adapter.go` — Red Hat two-phase adapter

## Bugs

### 1. NVD adapter returns nil NextCursor on final page — cursor regresses on every run

**Location:** `internal/feed/nvd/adapter.go:143-158` + `internal/ingest/handler.go:115-117`
**Severity:** minor (operational inefficiency, not data loss)

**Evidence:** When `computeNextCursor()` returns nil (all windows up to effectiveNow exhausted), the NVD `Fetch` method returns `NextCursor: nil, LastPage: true` (line 157-158). The ingest handler at line 115-117 only updates `lastSuccessfulCursor` when `result.NextCursor != nil`:

```go
if result.NextCursor != nil {
    lastSuccessfulCursor = result.NextCursor
}
```

So on the NVD's final page, `lastSuccessfulCursor` retains the *previous* page's cursor. This is persisted as the "success" cursor at line 189.

**Impact:** On every subsequent scheduled NVD run, the adapter starts from the penultimate window's cursor instead of a "caught up to effectiveNow" cursor. This causes 1-4 extra NVD API calls per run (re-querying the last window which returns few/zero results, then receiving nil NextCursor again). At NVD's 6s rate limit (or 0.6s with API key), this is 6-24 seconds of unnecessary API calls per 2-hour cycle. Not catastrophic, but the pattern is fragile — any future adapter that returns nil NextCursor on its final page will silently regress its cursor.

**Root cause:** The FetchResult contract has an ambiguity: nil NextCursor simultaneously means "no more pages" (termination signal) and "I have no cursor to persist" (loss of state). The NVD adapter uses it for termination but the handler interprets it as "no cursor update."

**Fix options:**
- (A) NVD adapter: always return a non-nil cursor, even when done. The "done" cursor would be `{WindowStart: effectiveNow - overlap, WindowEnd: effectiveNow, StartIndex: 0}` — a no-op window for the next run.
- (B) Ingest handler: when `result.LastPage && result.NextCursor == nil`, set `lastSuccessfulCursor = cursor` (preserve the cursor that was passed *to* this Fetch call rather than regressing).

### 2. Scheduler `NewSchedulerWithRegistry` mutates package-level Prometheus vars without synchronization

**Location:** `internal/ingest/scheduler.go:67-78`
**Severity:** minor (data race in tests)

**Evidence:** `NewSchedulerWithRegistry` reassigns the package-level variables `feedJobsEnqueued` and `feedJobsSkipped` (lines 67-74) without synchronization:

```go
func NewSchedulerWithRegistry(st SchedulerStore, reg prometheus.Registerer) *Scheduler {
    feedJobsEnqueued = promauto.With(reg).NewCounterVec(...)
    feedJobsSkipped = promauto.With(reg).NewCounterVec(...)
    ...
}
```

The `tick()` method (line 101-105) reads these same package-level vars via `feedJobsEnqueued.WithLabelValues(...)`. If two test goroutines call `NewSchedulerWithRegistry` and `tick()` concurrently (e.g., parallel test cases with isolated registries), this is a data race under `-race`.

**Impact:** Only affects test code using `NewSchedulerWithRegistry` with `t.Parallel()`. Production code uses `NewScheduler` which doesn't touch these vars. A `go test -race` run with concurrent scheduler tests would trigger a data race warning.

**Fix:** Make the counter vecs fields on the `Scheduler` struct instead of package-level vars. `NewSchedulerWithRegistry` would set the struct fields, and `maybeEnqueue` would read from `s.feedJobsEnqueued` instead of the package global.

## Design Concerns

### Ingest handler's `lastSuccessfulCursor` contract is implicitly coupled to adapter behavior

The ingest handler (handler.go:74-145) tracks `lastSuccessfulCursor` as a "checkpoint for crash recovery." The logic assumes that every adapter returns a non-nil `NextCursor` after processing data successfully. This assumption holds for 6 of 7 adapters (GHSA, KEV, MITRE, OSV, MSRC, Red Hat all return non-nil cursors even on their final page). But the NVD adapter breaks this assumption, and nothing in the `FetchResult` contract enforces it.

If a future adapter is implemented that returns `NextCursor: nil` on the last page (following NVD's pattern), the same cursor regression bug will appear silently. The `FetchResult` doc comment at `interface.go:28-30` says "Nil means no additional pages" but doesn't address what happens to cursor persistence when nil is returned on the final page.

Recommendation: either document that adapters MUST return a non-nil NextCursor carrying their "sync complete" state even on the last page, or make the handler explicitly handle the nil-NextCursor-with-LastPage case.

### Store job methods inconsistently use direct queries vs transaction helpers

`ClaimJob`, `CompleteJob`, `FailJob`, `RecoverStaleJobs`, and `EnqueueJob` in `store/jobs.go` use `s.q` directly (bound to the raw pool), while `HasPendingOrRunningJob` uses `s.withBypassTx`. The `jobs` table is not org-scoped and has no RLS, so this doesn't cause a correctness issue today. But the inconsistency makes it easy to accidentally follow the `s.q` pattern when adding future job methods that *do* need transaction helpers.

### MSRC adapter doesn't drain oversized CSAF response bodies before close

In `msrc/adapter.go:394-395`, `io.ReadAll(io.LimitReader(csafResp.Body, maxCSAFDocSize))` reads up to 50MB, then `csafResp.Body.Close()` is called without draining any remaining bytes. If a CSAF document exceeds 50MB, the HTTP connection won't be reused. This is a minor connection-pool efficiency issue — for 50MB+ documents, the cost of a new TCP connection is negligible relative to the transfer cost.

### Red Hat adapter cannot populate DateModified (API limitation)

The Red Hat Security Data API does not provide a `last_modified` or `updated_at` field on CVE detail records — only `public_date`. Consequently, `detailToPatch()` in `redhat/adapter.go:184-258` never sets `patch.DateModified`. This means `cve_sources.source_date_modified` is always NULL for Red Hat rows, and Red Hat changes don't contribute to `cves.date_modified_source_max`. The batch alert evaluator uses `date_modified_canonical` (which is always bumped by the merge pipeline), so alerts are not affected. This is a data quality gap, not a correctness issue.