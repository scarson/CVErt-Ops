# Feed Adapter Wiring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Use superpowers:test-driven-development for every task that creates new code.

**Goal:** Wire the existing 6 feed adapters (NVD, MITRE, KEV, EPSS, GHSA, OSV) into the worker pool so they actually fetch data, run through the merge pipeline, and persist sync state — then expose feed health via an admin API and dashboard UI.

**Architecture:** The worker pool already polls the `feed_ingest` queue. We replace the stub `feedIngestHandler` with a real handler that deserializes the job payload to identify the feed, constructs the appropriate adapter, calls `Fetch()` in a pagination loop, pipes each `CanonicalPatch` through `merge.Ingest()`, and persists cursor/sync state. A scheduler goroutine periodically enqueues `feed_ingest` jobs respecting per-feed intervals and backoff. EPSS is special — it doesn't implement `feed.Adapter`, so it gets its own dedicated handler and queue. Two admin API endpoints expose feed health. The frontend `FeedStatusView.vue` replaces its "Coming Soon" placeholder with a real dashboard.

**Tech Stack:** Go 1.26, sqlc, huma/chi, Vue 3 + shadcn-vue, existing `internal/feed/*` adapters, `internal/merge` pipeline, `internal/worker` pool, `internal/store` (sqlc queries for `feed_sync_state` / `feed_fetch_log`)

**Package structure note:** Handlers and scheduler live in a NEW `internal/ingest/` package — NOT in `internal/feed/`. This avoids circular dependencies: `internal/merge` imports `internal/feed` (for `CanonicalPatch`), and all feed sub-packages (`nvd`, `mitre`, etc.) import `internal/feed`. Placing orchestration code in `internal/ingest/` lets it import `internal/feed`, `internal/feed/*`, `internal/merge`, and `internal/store` without cycles.

---

## Task 1: Add sqlc queries and store wrappers for feed state

We need two new queries the admin API and scheduler will use: one to list all feed sync states, one to list recent fetch logs for a given feed. We also need store wrapper methods so the feed package can access feed state without importing the generated package directly.

**Files:**
- Modify: `internal/store/queries/feed.sql`
- Regenerate: `internal/store/generated/feed.sql.go` (via `sqlc generate`)
- Create: `internal/store/feed.go` — wrapper methods for feed state operations
- Create: `internal/store/feed_test.go` — basic integration tests

**Step 1: Add the new queries to feed.sql**

Append these two queries after the existing `InsertFeedFetchLog`:

```sql
-- name: ListFeedSyncStates :many
SELECT * FROM feed_sync_state ORDER BY feed_name;

-- name: ListRecentFeedFetchLogs :many
SELECT * FROM feed_fetch_log
WHERE feed_name = $1
ORDER BY started_at DESC
LIMIT $2;
```

**Step 2: Regenerate sqlc**

Run: `sqlc generate`
Expected: no errors. Verify `internal/store/generated/feed.sql.go` now contains `ListFeedSyncStates` and `ListRecentFeedFetchLogs` functions.

**Step 3: Write failing integration tests (TDD — test first)**

Create `internal/store/feed_test.go` BEFORE the implementation:
- Test `UpsertFeedSyncState` + `GetFeedSyncState` round-trip
- Test `InsertFeedFetchLog` + `ListRecentFeedFetchLogs` returns correct order and limit
- Test `ListFeedSyncStates` returns all states ordered by name
- Test `GetFeedSyncState` returns nil for nonexistent feed (nil, nil — not an error)

Follow the test DB setup pattern used in existing store tests (e.g., `internal/store/jobs_test.go`).

**Step 4: Run tests to confirm they fail**

Run: `go test ./internal/store/ -run TestFeed -v`
Expected: FAIL — wrapper methods don't exist yet.

**Step 5: Create store wrapper methods**

Create `internal/store/feed.go` with domain types and wrapper methods that other packages (like `internal/ingest/` and `internal/api/`) can use without importing the generated package:

```go
// ABOUTME: Store methods for feed sync state and fetch log persistence.
// ABOUTME: Wraps sqlc-generated queries with domain types for use by feed handlers and admin API.
package store
```

Define a `FeedSyncState` domain struct (mirroring the generated model but with cleaner types) and wrapper methods:
- `GetFeedSyncState(ctx, feedName) -> (*FeedSyncState, error)` — returns nil, nil when not found (wraps `sql.ErrNoRows`)
- `UpsertFeedSyncState(ctx, state FeedSyncState) error`
- `InsertFeedFetchLog(ctx, log FeedFetchLog) (uuid.UUID, error)`
- `ListFeedSyncStates(ctx) ([]FeedSyncState, error)`
- `ListRecentFeedFetchLogs(ctx, feedName string, limit int) ([]FeedFetchLog, error)`

These use `withBypassTx` since feed state is global (not org-scoped) — same pattern as `CleanupFeedFetchLog` in `internal/store/retention.go`.

**Step 6: Run tests to confirm they pass**

Run: `go test ./internal/store/ -run TestFeed -v`
Expected: PASS

**Step 7: Commit**

```
feat: add feed state sqlc queries and store wrapper methods
```

---

## Task 2: Wire the real `feedIngestHandler` for standard adapters

Replace the stub in `cmd/cvert-ops/main.go` with a real handler that:
1. Unmarshals the job payload to get the feed name
2. Reads the current cursor from `feed_sync_state`
3. Constructs the right adapter (NVD, MITRE, KEV, GHSA, OSV — **not** EPSS)
4. Calls `Fetch()` in a loop (paginating via `NextCursor`)
5. For each patch, calls `merge.Ingest()`
6. On success: persists new cursor + success state to `feed_sync_state`, logs to `feed_fetch_log`
7. On failure: persists failure state (consecutive_failures++, backoff_until, last_error)

EPSS is handled separately in Task 3 because it does not implement `feed.Adapter`.

**Files:**
- Create: `internal/ingest/handler.go` — the handler function + adapter factory
- Create: `internal/ingest/feeds.go` — shared `KnownFeeds` constant and adapter factory
- Modify: `cmd/cvert-ops/main.go` — replace stub, pass dependencies

**Step 1: Write the failing test**

Create `internal/ingest/handler_test.go`. Since `internal/ingest/` can import `internal/merge` directly, no function injection is needed. However, the test should avoid depending on the full merge pipeline + DB. Use a mock merge function that records calls:

**Unit test approach (preferred for the handler logic):**
- Define a local `mergeFunc` variable in the test that records `(patch, sourceName)` pairs and returns nil
- Create a mock adapter implementing `feed.Adapter` that returns a fixed `FetchResult` with one `CanonicalPatch` and `NextCursor: nil` (single page)
- Use a real test DB for the store (feed_sync_state/feed_fetch_log persistence)
- Call the handler directly (pass the mock merge function — see Step 3 for how the handler accepts it)
- Assert the mock merge function was called with the correct patch
- Assert `feed_sync_state` is updated with the new cursor (query the DB)
- Assert `feed_fetch_log` gets a success entry

Also test the error path:
- Mock adapter that returns an error from Fetch
- Assert `feed_sync_state` has `consecutive_failures = 1` and non-empty `last_error`
- Assert `feed_fetch_log` has status `"error"`

Also test multi-page cursor persistence on mid-pagination error:
- Mock adapter that succeeds on page 1 (returns NextCursor="page2"), then errors on page 2
- Assert `feed_sync_state` cursor is set to the page 1 cursor (last successful NextCursor), NOT the original cursor

Follow the existing test patterns in `internal/feed/nvd/adapter_test.go` or `internal/store/jobs_test.go` for test DB setup. Check how other integration tests set up their database and match that pattern exactly.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ingest/ -run TestFeedIngestHandler -v`
Expected: FAIL — package doesn't exist yet.

**Step 3: Write the implementation**

Create `internal/ingest/feeds.go` first — shared constants and adapter factory:

```go
// ABOUTME: Shared feed name constants and adapter factory for feed ingestion.
// ABOUTME: Maps feed names to their concrete adapter constructors.
package ingest
```

**Known feeds constant:**
```go
// KnownFeeds is the canonical set of feed names. Used for validation in both
// the ingest handler and admin API.
var KnownFeeds = []string{"nvd", "mitre", "kev", "ghsa", "osv", "epss"}

// IsKnownFeed returns true if feedName is a recognized feed.
func IsKnownFeed(feedName string) bool
```

**Adapter factory function** — returns the right `feed.Adapter` given a feed name:
```go
func NewAdapter(feedName string, client *http.Client) (feed.Adapter, error)
```
Maps: `"nvd"` → `nvd.New(client)`, `"mitre"` → `mitre.New(client)`, `"kev"` → `kev.New(client)`, `"ghsa"` → `ghsa.New(client)`, `"osv"` → `osv.New(client)`. Returns error for unknown feed name or `"epss"` (EPSS has a separate handler — Task 3).

Then create `internal/ingest/handler.go`:

```go
// ABOUTME: Feed ingestion handler for the worker pool — fetches from adapters and merges into CVE corpus.
// ABOUTME: Handles cursor persistence, sync state tracking, and fetch logging for all standard adapters.
package ingest
```

**No circular dependency issues:** `internal/ingest/` is a new orchestration package that can freely import `internal/feed`, `internal/feed/nvd`, `internal/merge`, `internal/store`, etc.

**Payload struct:**
```go
type IngestPayload struct {
    FeedName string `json:"feed_name"`
}
```

**MergeFunc type** — used for testability (allows injecting a mock in tests):
```go
// MergeFunc matches the signature of merge.Ingest. Defined as a type for test injection.
type MergeFunc func(ctx context.Context, s *store.Store, patch feed.CanonicalPatch, sourceName string, rawPayload json.RawMessage) error
```

**Handler factory** — returns a `worker.Handler` closure:
```go
func IngestHandler(st *store.Store, client *http.Client, mergeFn MergeFunc) worker.Handler
```

In production, pass `merge.Ingest` directly: `ingest.IngestHandler(st, client, merge.Ingest)`. In tests, pass a recording mock.

The returned handler function:
1. Unmarshal `IngestPayload` from `json.RawMessage`
2. Call `NewAdapter(payload.FeedName, client)` to get the right adapter
3. Read current cursor: `st.GetFeedSyncState(ctx, payload.FeedName)` — if nil (not found), treat as first run with nil cursor and `consecutiveFailures = 0`
4. Record `cursorBefore` for fetch log
5. **Pagination loop:** call `adapter.Fetch(ctx, cursor)`, iterate `result.Patches`, call `mergeFn(ctx, st, patch, result.SourceMeta.SourceName, result.RawPayload)` for each patch. Track `itemsFetched` and `itemsUpserted` counters. After each successful page, save `lastSuccessfulCursor = result.NextCursor`. Set `cursor = result.NextCursor`. Break when `NextCursor` is nil.
6. On success: `st.UpsertFeedSyncState` with final cursor, `last_success_at = now`, `consecutive_failures = 0`, `last_error = ""`, `backoff_until = zero`. `st.InsertFeedFetchLog` with status `"success"`.
7. On error (from Fetch or merge): persist `lastSuccessfulCursor` (the cursor from the last fully-processed page, NOT the original pre-run cursor — this avoids re-fetching already-merged pages on retry). `st.UpsertFeedSyncState` with `lastSuccessfulCursor`, `last_attempt_at = now`, `consecutive_failures = prevFailures + 1`, `last_error = err.Error()`, `backoff_until = now + backoffDuration(prevFailures+1)`. `st.InsertFeedFetchLog` with status `"error"`. Return the error so the worker pool marks the job as failed. If `lastSuccessfulCursor` is nil (failed on the first page), fall back to the original cursor.

**Important:** `FetchResult.RawPayload` is the raw upstream response for the entire page/batch, not per-patch. Passing the full page payload to `merge.Ingest` for every patch on that page is correct — `cve_raw_payloads` stores the full source response associated with each CVE for audit purposes. This may result in the same payload being stored multiple times (once per CVE on the page), which is acceptable for audit traceability.

**Backoff calculation:**
```go
func backoffDuration(failures int32) time.Duration {
    base := 30 * time.Second
    d := base * time.Duration(1<<min(failures, 10)) // exponential, cap at ~8.5 hours
    return d
}
```

**Counting upserts:** `merge.Ingest` doesn't currently return whether the CVE was actually changed (material_hash differed). For now, count every `merge.Ingest` call that returns nil as an upsert. This is an overcount but acceptable for operational logging. Do NOT modify `merge.Ingest`'s signature for this.

**Logging requirements (use `slog`):**
- On handler entry: `slog.Info("feed ingest started", "feed", feedName)`
- After each page: `slog.Info("feed page fetched", "feed", feedName, "page_items", len(result.Patches), "total_fetched", itemsFetched, "has_next", result.NextCursor != nil)`
- On merge error for a single patch: `slog.Error("feed merge failed", "feed", feedName, "cve_id", patch.CVEID, "error", err)` — then fail the whole job (don't skip individual patches)
- On success: `slog.Info("feed ingest completed", "feed", feedName, "items_fetched", itemsFetched, "items_upserted", itemsUpserted, "duration", time.Since(start))`
- On error: `slog.Error("feed ingest failed", "feed", feedName, "items_fetched", itemsFetched, "error", err, "duration", time.Since(start))`

Record `start := time.Now()` at handler entry for duration logging.

**Step 4: Wire into main.go**

In `cmd/cvert-ops/main.go`, replace the stub:
```go
// Before (delete this):
func feedIngestHandler(_ context.Context, payload json.RawMessage) error { ... }

// After — in both runServe() and runWorker(), create a shared feed HTTP client
// and register the handler. merge.Ingest is passed directly (no circular dependency
// since internal/ingest/ is a separate package from internal/feed/):
feedClient := &http.Client{Timeout: 5 * time.Minute}
workerPool.Register("feed_ingest", ingest.IngestHandler(st, feedClient, merge.Ingest))
```

Add import: `ingest "github.com/scarson/cvert-ops/internal/ingest"`

Create `feedClient` in both `runServe()` and `runWorker()` — each function builds its own dependency tree independently. Each adapter manages its own rate limiter internally. The 5-minute timeout is generous because MITRE and OSV adapters download bulk ZIP archives that can take time on slow connections.

**Step 5: Run test to verify it passes**

Run: `go test ./internal/ingest/ -run TestFeedIngestHandler -v`
Expected: PASS

**Step 6: Run full test suite**

Run: `go test ./...`
Expected: all tests pass (existing + new).

**Step 7: Commit**

```
feat: wire feed ingest handler to worker pool with merge pipeline integration
```

---

## Task 3: Wire the EPSS handler

EPSS does not implement `feed.Adapter`. It has its own `Apply(ctx, store, cursor) -> (newCursor, error)` method that handles DB writes directly (two-statement pattern with advisory locks). It needs a dedicated worker handler.

**Files:**
- Create: `internal/ingest/epss.go` — EPSS-specific handler
- Modify: `cmd/cvert-ops/main.go` — register on `"epss_ingest"` queue

**Step 1: Write the failing test**

Create `internal/ingest/epss_test.go`. Testing EPSS is tricky because:
- `epss.Adapter` has a hardcoded `feedURL` constant for the EPSS download endpoint
- `Apply()` takes a `*store.Store` and writes directly to the DB

The best approach: write an integration test that uses `httptest.NewServer` to serve a minimal gzip-compressed EPSS CSV, then construct the adapter with an HTTP client whose transport redirects requests to the test server. Check how `internal/feed/epss/adapter_test.go` handles this — it likely already has a pattern for overriding the URL or using a test server. Match that pattern.

Test assertions:
- `feed_sync_state` for `"epss"` is updated with new cursor
- `feed_fetch_log` gets a success entry
- On error, `consecutive_failures` increments

Follow the same test DB setup pattern used in Task 2.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/ingest/ -run TestEPSSIngestHandler -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `internal/ingest/epss.go`:

```go
// ABOUTME: EPSS feed handler for the worker pool — applies daily EPSS scores to the CVE corpus.
// ABOUTME: Wraps the EPSS adapter's Apply() method with sync state tracking and fetch logging.
package ingest
```

**Handler factory:**
```go
func EPSSIngestHandler(st *store.Store, client *http.Client) worker.Handler
```

`internal/ingest/` can import `internal/feed/epss` directly — no dependency cycle.

The returned handler:
1. Ignores the payload (EPSS has no configurable parameters)
2. Reads current cursor: `st.GetFeedSyncState(ctx, "epss")` — nil means first run
3. Constructs `epss.New(client)`
4. Calls `adapter.Apply(ctx, st, cursorJSON)`
5. On success: `st.UpsertFeedSyncState` with new cursor, success state. `st.InsertFeedFetchLog` with status `"success"`. Note: EPSS doesn't return item counts, so set `items_fetched = 0` and `items_upserted = 0` (the adapter logs internally).
6. On error: same failure pattern as Task 2 (increment failures, set backoff, log error). Use `st.UpsertFeedSyncState` and `st.InsertFeedFetchLog`.

**Logging requirements (use `slog`):**
- On handler entry: `slog.Info("epss ingest started")`
- On success: `slog.Info("epss ingest completed", "duration", time.Since(start))`
- On error: `slog.Error("epss ingest failed", "error", err, "duration", time.Since(start))`

Note: The EPSS adapter itself already logs per-row warnings (unparseable scores, model version changes). The handler only needs to log start/end/duration.

**Step 4: Wire into main.go**

In both `runServe()` and `runWorker()`, add after the existing `feed_ingest` registration:
```go
workerPool.Register("epss_ingest", ingest.EPSSIngestHandler(st, &http.Client{
    Timeout: 300 * time.Second, // EPSS downloads ~15MB gzip; allow generous timeout
}))
```

(Uses the same `ingest` import added in Task 2.)

**Step 5: Run tests**

Run: `go test ./internal/ingest/ -run TestEPSS -v`
Expected: PASS

**Step 6: Run full test suite**

Run: `go test ./...`
Expected: all pass.

**Step 7: Commit**

```
feat: wire EPSS ingest handler to worker pool
```

---

## Task 4: Feed scheduler

Add a goroutine that periodically checks whether each feed is due for a sync and enqueues `feed_ingest` / `epss_ingest` jobs accordingly. A feed is "due" when `last_success_at + interval <= now` (or when it has never synced). The scheduler also skips feeds with a pending/running job to avoid double-scheduling.

**Files:**
- Create: `internal/ingest/scheduler.go`
- Create: `internal/ingest/scheduler_test.go`
- Modify: `internal/config/config.go` — add scheduler enable flag
- Modify: `cmd/cvert-ops/main.go` — start scheduler goroutine
- Modify: `.env.example` — document `FEED_SCHEDULER_ENABLED`

**Step 1: Add config fields**

Add to `internal/config/config.go` in the `Config` struct:

```go
FeedSchedulerEnabled bool `env:"FEED_SCHEDULER_ENABLED" envDefault:"true"`
```

No per-feed interval config for now — use the intervals from PLAN.md §3.1 as hardcoded defaults (NVD: 2h, MITRE: 24h, KEV: 24h, GHSA: 6h, OSV: 24h, EPSS: 24h). Per-feed config can be added later if needed (YAGNI).

**Step 2: Write the failing test**

Create `internal/ingest/scheduler_test.go`. Test that:
- `Scheduler.tick()` enqueues jobs for feeds that have never synced (`GetFeedSyncState` returns nil)
- `Scheduler.tick()` enqueues jobs for feeds where `last_success_at + interval <= now`
- `Scheduler.tick()` skips feeds where `last_success_at + interval > now` (not yet due)
- `Scheduler.tick()` skips feeds that already have a pending/running job (via `HasPendingOrRunningJob`)
- It uses `"epss_ingest"` queue for EPSS and `"feed_ingest"` queue for all others

Use a `SchedulerStore` interface with a mock implementation for unit testing (not integration — the scheduler's logic is pure scheduling, no DB queries beyond the interface). Define the mock in the test file.

**Step 3: Run test to verify it fails**

Run: `go test ./internal/ingest/ -run TestScheduler -v`
Expected: FAIL

**Step 4: Write the implementation**

Create `internal/ingest/scheduler.go`:

```go
// ABOUTME: Periodically enqueues feed ingestion jobs based on configured intervals.
// ABOUTME: Checks sync state timing and deduplicates to avoid double-scheduling.
package ingest
```

**Feed schedule definitions** (use `KnownFeeds` from `feeds.go` for consistency):
```go
var defaultSchedule = []feedScheduleEntry{
    {FeedName: "nvd", Queue: "feed_ingest", Interval: 2 * time.Hour},
    {FeedName: "mitre", Queue: "feed_ingest", Interval: 24 * time.Hour},
    {FeedName: "kev", Queue: "feed_ingest", Interval: 24 * time.Hour},
    {FeedName: "ghsa", Queue: "feed_ingest", Interval: 6 * time.Hour},
    {FeedName: "osv", Queue: "feed_ingest", Interval: 24 * time.Hour},
    {FeedName: "epss", Queue: "epss_ingest", Interval: 24 * time.Hour},
}
```

**Scheduler struct and store interface:**
```go
type Scheduler struct {
    store    SchedulerStore
    schedule []feedScheduleEntry
}

// SchedulerStore is the subset of store.Store the scheduler needs.
type SchedulerStore interface {
    GetFeedSyncState(ctx context.Context, feedName string) (*store.FeedSyncState, error)
    EnqueueJob(ctx context.Context, queue string, priority int32, payload json.RawMessage, lockKey *string, maxAttempts int32, runAfter *time.Time) (uuid.UUID, error)
    HasPendingOrRunningJob(ctx context.Context, lockKey string) (bool, error)
}
```

Note: `FeedSyncState` here is the domain type from `internal/store/feed.go` (Task 1). Import it as `store.FeedSyncState`. The `SchedulerStore` interface is satisfied by `*store.Store`. Since `internal/ingest/` is a separate package, it can freely import `internal/store`.

**Key method — `tick()`:** For each feed in the schedule:
1. Read `st.GetFeedSyncState(ctx, feedName)` — if nil (never synced), the feed is due
2. If state exists: check `state.LastSuccessAt + entry.Interval <= now`. If not due, skip.
3. Use `lock_key = "feed:" + feedName` for deduplication
4. Call `HasPendingOrRunningJob(ctx, lockKey)` — skip if true (already queued)
5. Call `EnqueueJob(ctx, queue, 0, payload, &lockKey, 3, nil)` where payload is `{"feed_name": feedName}`

**Logging requirements:**
- On enqueue: `slog.Info("feed job enqueued", "feed", feedName, "queue", queue)`
- On skip (not due): `slog.Debug("feed not yet due", "feed", feedName, "next_due", state.LastSuccessAt.Add(interval))` — use Debug level to avoid log spam every minute
- On skip (already queued): `slog.Debug("feed job already pending", "feed", feedName)`
- On error (from GetFeedSyncState, HasPendingOrRunningJob, or EnqueueJob): `slog.Error("scheduler error", "feed", feedName, "error", err)` — log and continue to next feed, don't abort the tick

**Start method:**
```go
func (s *Scheduler) Start(ctx context.Context)
```
Uses `time.NewTicker` (not `time.After` — timer leak prevention per project conventions). Tick interval: 1 minute. On each tick, calls `s.tick(ctx)`. Runs the first tick immediately on startup (so feeds start fetching on first boot without waiting). Blocks until `ctx` is cancelled.

**Step 5: Wire into main.go**

In both `runServe()` and `runWorker()`, start the scheduler goroutine alongside the worker pool:

```go
if cfg.FeedSchedulerEnabled {
    feedScheduler := ingest.NewScheduler(st)
    go feedScheduler.Start(ctx)
}
```

Place this BEFORE `go workerPool.Start(ctx)` so the scheduler is running when the pool starts claiming jobs.

**Step 6: Update `.env.example`**

Add `FEED_SCHEDULER_ENABLED=true` with a comment explaining it controls the feed scheduler. Check if `.env.example` exists first — if not, skip this step (document in the commit message that the env var should be added when `.env.example` is created).

**Step 7: Run tests**

Run: `go test ./internal/ingest/ -run TestScheduler -v`
Expected: PASS

**Step 8: Run full test suite**

Run: `go test ./...`
Expected: all pass.

**Step 9: Commit**

```
feat: add feed scheduler for periodic ingestion job enqueueing
```

---

## Task 5: Admin feeds API

Two endpoints per PLAN.md Appendix B:
- `GET /api/v1/admin/feeds` — list all feed sync states + recent fetch logs
- `POST /api/v1/admin/feeds/{feed}/run` — manually trigger a feed re-run

These are system-level endpoints, not org-scoped. They operate on global feed state (the `feed_sync_state` and `feed_fetch_log` tables have no `org_id`).

**Auth approach:** For MVP, require authentication (`RequireAuth` middleware) but no org-role check — any authenticated user can view feed status and trigger re-runs. Feed data is public CVE data, not tenant-sensitive. A proper system-admin role can be added later. Check `internal/api/server.go` to see how `RequireAuth` is used on other non-org-scoped routes (like the auth providers endpoint) and follow that pattern.

**Files:**
- Create: `internal/api/feeds.go` — handler implementations
- Create: `internal/api/feeds_test.go` — integration tests
- Modify: `internal/api/server.go` — register routes

**Step 1: Write the failing test**

Create `internal/api/feeds_test.go`:

Test `GET /api/v1/admin/feeds`:
- Seed `feed_sync_state` with two rows (e.g., "nvd" with success state, "kev" with failure state) using `st.UpsertFeedSyncState`
- Seed `feed_fetch_log` with a few rows using `st.InsertFeedFetchLog`
- Call the endpoint with an authenticated user (use the same test auth helper as other API tests)
- Assert 200 response
- Assert response body contains both feed states
- Assert each feed state includes its recent fetch logs array

Test `POST /api/v1/admin/feeds/{feed}/run`:
- Call with feed name "nvd"
- Assert 202 response
- Assert a job was enqueued on the `"feed_ingest"` queue (query `job_queue` table)
- Call with feed name "epss"
- Assert a job was enqueued on the `"epss_ingest"` queue
- Call with unknown feed name like "bogus"
- Assert 400 error

Test auth:
- Call `GET /api/v1/admin/feeds` without auth header
- Assert 401

Follow the existing test patterns in `internal/api/auth_test.go` for API test setup (test server creation, JWT generation, request helpers).

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -run TestAdminFeeds -v`
Expected: FAIL

**Step 3: Write the implementation**

Create `internal/api/feeds.go`:

```go
// ABOUTME: Admin API handlers for feed status monitoring and manual triggering.
// ABOUTME: Exposes feed_sync_state and feed_fetch_log data; enqueues manual re-run jobs.
package api
```

**List feeds handler:**
- Output struct includes an array of feed entries, each with sync state fields + recent fetch logs (last 5)
- Calls `srv.store.ListFeedSyncStates(ctx)` to get all states
- For each state, calls `srv.store.ListRecentFeedFetchLogs(ctx, feedName, 5)` to get recent logs
- Returns the combined result

**Trigger feed handler:**
- Input: feed name from URL path
- Validate feed name using `ingest.IsKnownFeed(feedName)` (shared constant from `internal/ingest/feeds.go`)
- Determine the queue: `"epss_ingest"` for EPSS, `"feed_ingest"` for all others
- Use lock_key `"feed:" + feedName` for deduplication
- Check `HasPendingOrRunningJob` — if true, return 409 Conflict with "feed job already pending"
- Enqueue the job, return 202 Accepted with the job ID

**Step 4: Register routes in server.go**

Register the admin routes in `internal/api/server.go`. These go inside the authenticated API group but outside any org-scoped group. Look at how the existing route tree is structured and find the right place to insert:

```go
r.Route("/admin", func(r chi.Router) {
    r.Get("/feeds", srv.listFeedsHandler)
    r.Post("/feeds/{feed}/run", srv.triggerFeedHandler)
})
```

This should be inside the `r.Group` that applies `RequireAuth` middleware, at the same level as org-scoped routes. Read `internal/api/server.go` carefully to find the correct insertion point — the route tree structure matters for middleware application.

Register these routes using `huma.Register` with proper `huma.Operation` structs (matching the pattern used in `auth.go` for `authProvidersHandler`). The huma framework provides automatic OpenAPI documentation and request/response validation.

**Step 5: Run tests**

Run: `go test ./internal/api/ -run TestAdminFeeds -v`
Expected: PASS

**Step 6: Run full test suite**

Run: `go test ./...`
Expected: all pass.

**Step 7: Commit**

```
feat: add admin feeds API for status monitoring and manual triggering
```

---

## Task 6: Feed status dashboard UI

Replace the "Coming Soon" placeholder in `FeedStatusView.vue` with a real dashboard showing feed health.

**Files:**
- Modify: `web/src/views/FeedStatusView.vue` — real dashboard
- Modify: `web/src/views/__tests__/FeedStatusView.test.ts` — update tests

**Step 1: Write the failing test**

Update `web/src/views/__tests__/FeedStatusView.test.ts`:
- Mock `fetch` to return feed status data (two feeds: one healthy, one failing)
- Assert the component renders a table/card for each feed showing: feed name, status badge (healthy/failing/never-synced), last success time, consecutive failures, last error
- Assert a "Run Now" button exists for each feed
- Assert clicking "Run Now" sends a POST to `/api/v1/admin/feeds/{feed}/run`

Check the existing test file first to understand what's already tested and what test utilities are available.

**Step 2: Run test to verify it fails**

Run: `cd web && npx vitest run src/views/__tests__/FeedStatusView.test.ts`
Expected: FAIL

**Step 3: Implement the dashboard**

Replace `FeedStatusView.vue` content. The component should:

1. **On mount:** Fetch feed status from `/api/v1/admin/feeds`. This endpoint requires auth but is NOT org-scoped, so don't use `orgFetch` (which prepends the org path). Instead, use a plain `fetch` with the auth token from the auth store. Check how other non-org-scoped authenticated requests are made in the frontend — look at the auth store's `token` getter and add an `Authorization: Bearer ${token}` header. If there's a shared `apiFetch` or similar utility that handles auth headers without org scoping, use that instead.
2. **Display:** A table with columns: Feed Name, Status (badge), Last Success, Failures, Last Error, Actions
3. **Status logic:**
   - `consecutive_failures === 0 && last_success_at !== null` → green "Healthy" badge
   - `consecutive_failures > 0` → red "Failing" badge with failure count
   - `last_success_at === null && consecutive_failures === 0` → gray "Never Synced" badge
4. **Run Now button:** POST to `/api/v1/admin/feeds/{feed}/run`. Show loading state. On 409 (already pending), show toast/inline message "Job already pending". On success, show "Job enqueued" and refresh the feed list.
5. **Recent fetch logs:** Expandable/collapsible section per feed showing last 5 fetch logs with status, items fetched/upserted, timestamps, error summary.
6. **Auto-refresh:** Poll every 30 seconds (use `setInterval` with cleanup in `onUnmounted`).

Use existing shadcn components: `Table`, `Badge`, `Button`, `Card`. Use `Loader2` for loading states. Match the styling patterns of `WatchlistListView.vue` (loading/error/empty states).

**Auth consideration:** This page is at `/admin/feeds` and the router already has this route defined. Check if the router guard restricts this to admin users. If not, the backend auth check is sufficient — a non-admin user will just see an error from the API.

**Step 4: Run tests**

Run: `cd web && npx vitest run src/views/__tests__/FeedStatusView.test.ts`
Expected: PASS

**Step 5: Run full frontend test suite**

Run: `cd web && npx vitest run`
Expected: all pass.

**Step 6: Commit**

```
feat: replace feed status placeholder with live dashboard
```

---

## Task 7: Lint, full test suite, and final commit

**Step 1: Run Go linter**

Run: `golangci-lint run`
Expected: no new warnings from our changes. Fix any that appear.

**Step 2: Run full Go test suite**

Run: `go test ./...`
Expected: all pass.

**Step 3: Run full frontend test suite**

Run: `cd web && npx vitest run`
Expected: all pass.

**Step 4: Fix any issues found, commit fixes**

**Step 5: Update bug hunt file**

Mark the `/admin/feeds` item in `dev/bug-hunt/2026-03-06-ui-walkthrough.md` as resolved.

**Step 6: Commit**

```
chore: mark feed status dashboard as complete in bug hunt tracker
```

---

## Dependency Graph

```
Task 1 (sqlc queries + store wrappers)
  ↓
Task 2 (ingest handler — internal/ingest/) ←── uses store wrappers + merge.Ingest
  ↓
Task 3 (EPSS handler — internal/ingest/) ←── same pattern, different adapter interface
  ↓
Task 4 (scheduler — internal/ingest/) ←── reads feed sync state (Task 1), enqueues jobs for Tasks 2+3
  ↓
Task 5 (admin API — internal/api/) ←── reads state via store wrappers (Task 1), uses ingest.IsKnownFeed
  ↓
Task 6 (dashboard UI) ←── calls admin API from Task 5
  ↓
Task 7 (lint + final check)
```

Tasks 2 and 3 could theoretically be done in parallel (independent handlers), but they share similar patterns and sequential execution avoids confusion. Tasks 5 and 6 could also be parallelized (backend vs frontend) but the UI depends on knowing the exact API response shape from Task 5.

## Package Dependency Diagram

```
cmd/cvert-ops/main.go
  ├── internal/ingest/   (NEW — handler.go, epss.go, scheduler.go, feeds.go)
  │     ├── internal/feed/          (for feed.Adapter, feed.CanonicalPatch)
  │     ├── internal/feed/nvd/      (adapter constructors)
  │     ├── internal/feed/mitre/
  │     ├── internal/feed/kev/
  │     ├── internal/feed/ghsa/
  │     ├── internal/feed/osv/
  │     ├── internal/feed/epss/
  │     ├── internal/merge/         (for merge.Ingest)
  │     └── internal/store/
  ├── internal/api/
  │     ├── internal/ingest/        (for ingest.IsKnownFeed)
  │     └── internal/store/
  └── internal/worker/
```

No cycles: `internal/merge/` → `internal/feed/` (for CanonicalPatch), `internal/ingest/` → both. `internal/feed/*` → `internal/feed/` only.

## Reference Files

When implementing, read these files for patterns and conventions:
- `internal/feed/interface.go` — `Adapter` interface, `FetchResult`, `CanonicalPatch`
- `internal/feed/epss/adapter.go` — EPSS `Apply()` method (does NOT implement `Adapter`)
- `internal/feed/nvd/adapter.go` — example adapter constructor `New(*http.Client)`
- `internal/merge/pipeline.go` — `merge.Ingest()` signature and behavior
- `internal/worker/pool.go` — `Handler` type, `Register()`, `RegisterWithConcurrency()`
- `internal/store/jobs.go` — `EnqueueJob()`, `HasPendingOrRunningJob()` signatures
- `internal/store/generated/feed.sql.go` — generated query functions and param types
- `internal/store/retention.go` — example of store wrapper using `withBypassTx` for global (non-org-scoped) data
- `cmd/cvert-ops/main.go` — where handlers are wired, how dependencies flow
- `internal/api/server.go` — route registration patterns
- `internal/api/auth.go` — example of a simple handler (authProvidersHandler)
- `web/src/views/WatchlistListView.vue` — Vue dashboard patterns (loading/error/table)
- `internal/config/config.go` — env var config struct patterns
