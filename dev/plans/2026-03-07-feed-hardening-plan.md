# Feed Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all bugs and design concerns identified by the three-way bug hunt analysis, making the feed adapter system production-ready.

**Architecture:** Fixes span SQL queries, Go handler/adapter code, a new migration for global admin role + job dedup index, and scheduler observability. The GHSA adapter is rearchitected from internal-pagination to one-page-per-Fetch to match the NVD/Red Hat pattern.

**Tech Stack:** Go 1.26, PostgreSQL 15+, sqlc, chi, Prometheus, Vitest (frontend)

**Worktree:** `.worktrees/feed-wiring/` on branch `feed-wiring`

**Test commands:**
- Go tests: `go -C .worktrees/feed-wiring test ./internal/... -count=1`
- Specific package: `go -C .worktrees/feed-wiring test ./internal/store/ -run TestName -count=1`
- Lint: `cd .worktrees/feed-wiring && golangci-lint run`
- sqlc: `cd .worktrees/feed-wiring && sqlc generate`
- Frontend: `cd .worktrees/feed-wiring/web && npx vitest run`

**Testing philosophy:** Many of these bugs slipped through because existing tests didn't verify the *data written to the database* — they tested control flow (status codes, error returns) but not the actual persisted values. Every fix must include a test that reads back the DB row and asserts the correct value is stored. Mock-based tests would not have caught B1, B2, or B6.

**Pristine test output (CLAUDE.md rule):** Several tasks add `slog.Warn` or `slog.Error` calls. Tests that intentionally trigger these code paths MUST capture log output to keep test output clean. Pattern:
```go
var buf bytes.Buffer
origHandler := slog.Default().Handler()
slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
t.Cleanup(func() { slog.SetDefault(slog.New(origHandler)) })
// ... test code that triggers expected log output ...
if !strings.Contains(buf.String(), "expected message") {
    t.Errorf("expected log message not found in: %s", buf.String())
}
```
Apply this pattern in Tasks 2, 7, 12, and 13 where tests trigger expected error/warning logs.

---

## Task 1: Fix InsertFeedFetchLog to persist started_at and ended_at (B1)

**Why tests didn't catch this:** Existing handler tests verified that `InsertFeedFetchLog` was called (no error return), but never read the resulting `feed_fetch_log` row back from the DB to verify `started_at` and `ended_at` had different values.

**Files:**
- Modify: `internal/store/queries/feed.sql` (InsertFeedFetchLog query)
- Regenerate: `internal/store/generated/feed.sql.go` (via `sqlc generate`)
- Modify: `internal/store/feed.go:76-95` (InsertFeedFetchLog store method — map StartedAt/EndedAt to params)
- Test: `internal/store/feed_test.go` (add or extend test)

**Step 1: Write a failing test**

In `internal/store/feed_test.go`, add `TestInsertFeedFetchLog_PersistsTimestamps`:

```go
func TestInsertFeedFetchLog_PersistsTimestamps(t *testing.T) {
    db := testutil.NewTestDB(t)
    ctx := context.Background()

    startTime := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
    endTime := time.Date(2026, 1, 1, 10, 5, 30, 0, time.UTC)

    id, err := db.InsertFeedFetchLog(ctx, store.FeedFetchLog{
        FeedName:      "nvd",
        StartedAt:     startTime,
        EndedAt:       &endTime,
        Status:        "success",
        ItemsFetched:  100,
        ItemsUpserted: 42,
    })
    if err != nil {
        t.Fatalf("insert: %v", err)
    }
    if id == uuid.Nil {
        t.Fatal("expected non-nil ID")
    }

    // Read back the row and verify timestamps are persisted correctly.
    logs, err := db.ListRecentFeedFetchLogs(ctx, "nvd", 1)
    if err != nil {
        t.Fatalf("list: %v", err)
    }
    if len(logs) != 1 {
        t.Fatalf("expected 1 log, got %d", len(logs))
    }

    log := logs[0]
    // started_at must match what we passed, not "now()"
    if !log.StartedAt.Equal(startTime) {
        t.Errorf("started_at = %v, want %v", log.StartedAt, startTime)
    }
    // ended_at must match what we passed, not "now()"
    if log.EndedAt == nil || !log.EndedAt.Equal(endTime) {
        t.Errorf("ended_at = %v, want %v", log.EndedAt, endTime)
    }
    // Sanity: duration should be ~5.5 minutes, not zero
    if log.EndedAt != nil {
        duration := log.EndedAt.Sub(log.StartedAt)
        if duration < 5*time.Minute {
            t.Errorf("duration = %v, want >= 5m (started_at and ended_at are probably both now())", duration)
        }
    }
}
```

**Step 2: Run test — expect FAIL** (started_at and ended_at will both be `now()`)

Run: `go -C .worktrees/feed-wiring test ./internal/store/ -run TestInsertFeedFetchLog_PersistsTimestamps -count=1`

**Step 3: Fix the SQL query**

Change `internal/store/queries/feed.sql` InsertFeedFetchLog:

```sql
-- name: InsertFeedFetchLog :one
INSERT INTO feed_fetch_log (
    feed_name, started_at, ended_at, status, items_fetched, items_upserted,
    cursor_before, cursor_after, error_summary
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id;
```

Run `cd .worktrees/feed-wiring && sqlc generate` to regenerate.

**Step 4: Update the store method**

In `internal/store/feed.go`, update `InsertFeedFetchLog` to pass `StartedAt` and `EndedAt` to the generated params. The generated params struct will now include `StartedAt` and `EndedAt` fields. Map:
- `StartedAt: log.StartedAt`
- `EndedAt: toNullTime(log.EndedAt)`

**Step 5: Run test — expect PASS**

**Step 6: Commit**

```
fix: persist started_at and ended_at in feed fetch logs
```

---

## Task 2: Stop silently discarding sync state and fetch log errors (B2)

**Why tests didn't catch this:** Tests used injected mock merge functions and verified the handler's return value, but never verified that `UpsertFeedSyncState` was actually called or succeeded. The `_ =` pattern silently ate errors.

**Files:**
- Modify: `internal/ingest/handler.go:127,136,157,165` (4 call sites)
- Modify: `internal/ingest/epss.go:50,59,73,81` (4 call sites)

**Step 1: Write failing tests**

The handler takes a `HandlerStore` interface. Create a thin wrapper struct that embeds a real `*store.Store` but overrides `UpsertFeedSyncState` to return an error. This tests real error propagation logic (not mock behavior — the wrapper is a one-line override, not a full mock).

```go
type failSyncStateStore struct {
    *store.Store
}

func (f *failSyncStateStore) UpsertFeedSyncState(ctx context.Context, state store.FeedSyncState) error {
    return fmt.Errorf("simulated sync state failure")
}
```

Test 1: **Success path** — adapter returns patches successfully, but sync state write fails. Verify the handler returns an error (so the job is retried and the cursor isn't lost).

Test 2: **Error path** — adapter returns an error, AND sync state write fails. Verify the handler returns the *original* fetch error (not the sync state error). Verify the sync state failure is logged (capture slog output — see "Pristine test output" note below).

For `InsertFeedFetchLog` failures: log with `slog.Error` but don't change the return value (fetch log is observability, not correctness).

**Pristine test output:** Tests that intentionally trigger `slog.Error` or `slog.Warn` must capture log output to keep test output clean. Use `slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))` at test start (restore original after), then assert the buffer contains the expected log messages.

**Step 2: Implement the fix**

In `handler.go`, change success-path sync state write (line 157):
```go
// Before:
_ = st.UpsertFeedSyncState(ctx, store.FeedSyncState{...})

// After:
if syncErr := st.UpsertFeedSyncState(ctx, store.FeedSyncState{...}); syncErr != nil {
    slog.Error("feed sync state write failed on success path",
        "feed", p.FeedName, "error", syncErr)
    return fmt.Errorf("persist sync state for %s: %w", p.FeedName, syncErr)
}
```

For error-path sync state write (line 127):
```go
if syncErr := st.UpsertFeedSyncState(ctx, store.FeedSyncState{...}); syncErr != nil {
    slog.Error("feed sync state write failed on error path",
        "feed", p.FeedName, "error", syncErr)
}
```

For all `InsertFeedFetchLog` calls (lines 136, 165):
```go
if _, logErr := st.InsertFeedFetchLog(ctx, ...); logErr != nil {
    slog.Error("feed fetch log write failed", "feed", p.FeedName, "error", logErr)
}
```

Apply the same pattern in `epss.go` (4 call sites: lines 50, 59, 73, 81).

**Step 3: Run tests — expect PASS**

Run: `go -C .worktrees/feed-wiring test ./internal/ingest/ -count=1`

**Step 4: Commit**

```
fix: propagate sync state errors on success path, log on error path
```

---

## Task 3: Fix expectedSchemaVersion constant (B3)

**Files:**
- Modify: `cmd/cvert-ops/main.go:529`

**Step 1: Change the constant**

```go
const expectedSchemaVersion = 29
```

Note: this will need to be updated again after Tasks 4 and 5 add migrations 000030 and 000031 — Task 14 handles the final update to 31.

**Step 2: Commit**

```
fix: update expectedSchemaVersion to match latest migration (29)
```

---

## Task 4: Add global admin role and gate admin routes (B4)

**Why tests didn't catch this:** There was no concept of site admin in the codebase. The test `TestAdminFeeds_RequiresAuth` verified auth was required but had no way to test authorization levels that didn't exist yet.

**Files:**
- Create: `migrations/000030_add_site_admin.up.sql`
- Create: `migrations/000030_add_site_admin.down.sql`
- Modify: `internal/store/queries/users.sql` (add `IsSiteAdmin` query, add `SetSiteAdmin` query)
- Regenerate: `internal/store/generated/` (via `sqlc generate`)
- Create: `internal/api/middleware_site_admin.go` (RequireSiteAdmin middleware)
- Test: `internal/api/middleware_site_admin_test.go`
- Modify: `internal/api/auth.go:112` (`registerHandler` — set first user as site admin)
- Modify: `internal/store/auth.go` (add `IsSiteAdmin`, `SetFirstSiteAdmin` store methods using `withBypassTx`)
- Modify: `internal/api/server.go:196-200` (add RequireSiteAdmin to admin routes)
- Modify: `internal/api/feeds_test.go` (update tests to use site admin user)

**Step 1: Create migration**

`000030_add_site_admin.up.sql`:
```sql
ALTER TABLE users ADD COLUMN is_site_admin boolean NOT NULL DEFAULT false;
```

`000030_add_site_admin.down.sql`:
```sql
ALTER TABLE users DROP COLUMN is_site_admin;
```

**Step 2: Add sqlc queries**

In `users.sql`, add:
```sql
-- name: IsSiteAdmin :one
SELECT is_site_admin FROM users WHERE id = $1;

-- name: SetFirstSiteAdmin :exec
-- Atomically promotes a user to site admin only if no admin exists yet.
-- Prevents race condition when two users register simultaneously.
UPDATE users SET is_site_admin = true
WHERE id = $1
  AND NOT EXISTS (SELECT 1 FROM users WHERE is_site_admin = true);
```

Run `sqlc generate`.

**Step 3: Write failing test for RequireSiteAdmin middleware**

Test that a non-admin authenticated user gets 403 on admin routes. Test that a site admin user gets 200.

**Step 4: Implement RequireSiteAdmin middleware**

```go
func (srv *Server) RequireSiteAdmin() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            userID, ok := r.Context().Value(ctxUserID).(uuid.UUID)
            if !ok {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }
            isAdmin, err := srv.store.IsSiteAdmin(r.Context(), userID)
            if err != nil {
                slog.Error("check site admin", "user_id", userID, "error", err)
                http.Error(w, "internal error", http.StatusInternalServerError)
                return
            }
            if !isAdmin {
                http.Error(w, "forbidden: site admin required", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

**Step 5: Set first registered user as site admin**

In `internal/api/auth.go:112` (`registerHandler`), after the `CreateUser` call (around line 151), add:

```go
// Promote first user to site admin (atomic — no-op if one already exists).
if err := srv.store.SetFirstSiteAdmin(ctx, user.ID); err != nil {
    slog.ErrorContext(ctx, "register: set first site admin", "error", err)
    // Non-fatal — user is created, they just won't be admin.
}
```

The `SetFirstSiteAdmin` store method must use `withBypassTx` since it runs outside org context. Add to `internal/store/auth.go`:

```go
func (s *Store) SetFirstSiteAdmin(ctx context.Context, userID uuid.UUID) error {
    return s.withBypassTx(ctx, func(q *generated.Queries) error {
        return q.SetFirstSiteAdmin(ctx, userID)
    })
}
```

Similarly, `IsSiteAdmin` must use `withBypassTx` (called from middleware before org context). Add to `internal/store/auth.go`:

```go
func (s *Store) IsSiteAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
    var isAdmin bool
    err := s.withBypassTx(ctx, func(q *generated.Queries) error {
        var err error
        isAdmin, err = q.IsSiteAdmin(ctx, userID)
        return err
    })
    return isAdmin, err
}
```

**Step 6: Wire middleware to admin routes**

```go
apiRouter.Route("/admin", func(r chi.Router) {
    r.Use(srv.RequireAuthenticated())
    r.Use(srv.RequireSiteAdmin())
    r.Get("/feeds", srv.listFeedsHandler)
    r.Post("/feeds/{feed}/run", srv.triggerFeedHandler)
})
```

**Step 7: Update feeds_test.go**

Existing tests register a user then call admin endpoints. Since the first registered user is automatically site admin, the existing happy-path tests should still pass. Add a test that registers TWO users, logs in as the second, and verifies 403 on admin endpoints.

**Step 8: Run tests — expect PASS**

**Step 9: Commit**

```
feat: add site admin role and gate admin feed endpoints
```

---

## Task 5: Add partial unique index for job dedup (B6)

**Files:**
- Create: `migrations/000031_job_queue_pending_lock_uq.up.sql`
- Create: `migrations/000031_job_queue_pending_lock_uq.down.sql`
- Modify: `internal/store/queries/jobs.sql` (change EnqueueJob to use ON CONFLICT DO NOTHING)
- Regenerate: `internal/store/generated/` (via `sqlc generate`)
- Modify: `internal/store/jobs.go` (EnqueueJob returns uuid.Nil when conflict)
- Modify: `internal/ingest/scheduler.go` (handle dedup at EnqueueJob return)
- Modify: `internal/api/feeds.go` (handle dedup at EnqueueJob return)
- Test: `internal/store/jobs_test.go`

**Step 1: Create migration**

`000031_job_queue_pending_lock_uq.up.sql`:
```sql
-- migrate:no-transaction
-- Prevent duplicate pending/running jobs with the same lock_key.
-- This eliminates the TOCTOU race between HasPendingOrRunningJob and EnqueueJob.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS job_queue_lock_key_pending_running_uq
    ON job_queue (lock_key) WHERE status IN ('pending', 'running');
```

`000031_job_queue_pending_lock_uq.down.sql`:
```sql
-- migrate:no-transaction
DROP INDEX CONCURRENTLY IF EXISTS job_queue_lock_key_pending_running_uq;
```

**Step 2: Write failing test**

Test that enqueueing two jobs with the same lock_key, where the first is still pending, results in the second returning `uuid.Nil` (conflict). Currently it would insert a duplicate.

**Step 3: Change EnqueueJob SQL**

```sql
-- name: EnqueueJob :one
INSERT INTO job_queue (queue, priority, payload, lock_key, max_attempts, run_after)
VALUES ($1, $2, $3, $4, $5, coalesce($6, now()))
ON CONFLICT DO NOTHING
RETURNING id;
```

Note: this changes the return to potentially return no rows. The sqlc generated code returns `sql.ErrNoRows` when `ON CONFLICT DO NOTHING` fires. Handle this in `store/jobs.go`. You'll need to import `database/sql` for `sql.ErrNoRows` and `errors` for `errors.Is`.

**Step 4: Update store method**

In `jobs.go`, handle `sql.ErrNoRows` from EnqueueJob:
```go
if errors.Is(err, sql.ErrNoRows) {
    return uuid.Nil, nil  // dedup: job already exists
}
```

**Step 5: Update callers**

In `scheduler.go:113`: check if returned ID is `uuid.Nil` — if so, log at debug level (already pending), don't log as enqueued. Remove the `HasPendingOrRunningJob` check — the DB constraint now handles it atomically.

In `api/feeds.go:80-94`: replace the `HasPendingOrRunningJob` + `EnqueueJob` pattern with just `EnqueueJob`. If ID is `uuid.Nil`, return 409 Conflict.

Update `SchedulerStore` interface to remove `HasPendingOrRunningJob` if it's no longer used anywhere. Check all callers first. If it's still used by tests, keep it.

**Step 6: Run tests — expect PASS**

**Step 7: Commit**

```
fix: eliminate TOCTOU race in job dedup with partial unique index
```

---

## Task 6: Fix backoffDuration panic on negative input (B9)

**Files:**
- Modify: `internal/ingest/handler.go:187-190`
- Test: `internal/ingest/handler_test.go`

**Step 1: Write failing test**

```go
func TestBackoffDuration_NegativeInput(t *testing.T) {
    // Should not panic on negative input (e.g., from DB corruption).
    d := backoffDuration(-1)
    if d < 0 {
        t.Errorf("backoffDuration(-1) = %v, want non-negative", d)
    }
}
```

**Step 2: Run test — expect PANIC**

**Step 3: Fix**

```go
func backoffDuration(failures int32) time.Duration {
    base := 30 * time.Second
    return base * time.Duration(1<<min(max(failures, 0), 10))
}
```

**Step 4: Run test — expect PASS**

**Step 5: Commit**

```
fix: clamp backoffDuration input to prevent panic on negative values
```

---

## Task 7: Standardize streaming JSON error handling (B7 + B8)

**Why tests didn't catch this:** Adapter tests used well-formed JSON fixtures. No test included a malformed record mid-stream to verify skip-vs-fail behavior.

**Files:**
- Modify: `internal/feed/kev/adapter.go:220-223` (change hard-fail to skip for recoverable errors)
- Modify: `internal/feed/nvd/adapter.go:394-397` (add error type check)
- (GHSA is handled by Task 8's rewrite — skip here)
- Test: `internal/feed/kev/adapter_test.go`
- Test: `internal/feed/nvd/adapter_test.go`

**Step 1: Write failing tests**

For KEV: test with a JSON array where one record has a type error (e.g., a number where a string is expected). Example fixture:
```json
[
  {"cveID": "CVE-2024-0001", "vendorProject": "Test", "product": "App", ...valid fields...},
  {"cveID": 12345, "vendorProject": "Bad"},
  {"cveID": "CVE-2024-0003", "vendorProject": "Test", "product": "App", ...valid fields...}
]
```
Verify the adapter returns records 1 and 3 (skipping the malformed record 2) and logs a warning.

For NVD: test with a response body containing a syntax error mid-stream. Use an `httptest.Server` that returns a JSON body with a truncated/corrupted record:
```json
{"vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}, {INVALID_JSON, {"cve": {"id": "CVE-2024-0003"}}]}
```
Verify the adapter returns only the records parsed before the syntax error and logs a warning. It should NOT return an error (partial results are better than none).

Capture and validate the `slog.Warn` output per the pristine test output pattern above.

**Step 2: Implement standardized pattern**

All three adapters should use this pattern inside their `dec.More()` loop:

```go
if err := dec.Decode(&rec); err != nil {
    var syntaxErr *json.SyntaxError
    if errors.As(err, &syntaxErr) {
        // Stream is corrupted — remaining records are unreliable.
        slog.Warn("JSON syntax error in feed stream, stopping parse",
            "feed", feedName, "error", err)
        break
    }
    // Type errors are recoverable — the decoder consumed the token.
    slog.Warn("skipping malformed record in feed stream",
        "feed", feedName, "error", err)
    continue
}
```

Apply to KEV (currently hard-fails on all errors) and NVD (currently continues on all errors). **Skip GHSA** — Task 8 rewrites the GHSA adapter's `Fetch()` method entirely; incorporate this streaming error pattern there instead.

**Step 3: Run tests — expect PASS**

**Step 4: Commit**

```
fix: standardize streaming JSON error handling across feed adapters
```

---

## Task 8: Rearchitect GHSA adapter to one-page-per-Fetch (B5)

**Why tests didn't catch this:** Tests verified the adapter returned correct patches for a single page of data, but didn't test multi-page scenarios or crash recovery, because the adapter hid pagination internally.

**Files:**
- Modify: `internal/feed/ghsa/adapter.go` (Fetch returns one page, cursor carries `after`)
- Test: `internal/feed/ghsa/adapter_test.go`

**Step 1: Write failing test**

Test that calling `Fetch` with a cursor containing an `after` value returns only one page of results with `LastPage: false` and a `NextCursor` containing the next `after` value. Currently it returns all pages with `LastPage: true`.

**Step 2: Redesign Fetch**

The GHSA adapter's `Fetch()` should:
1. Parse cursor (which now includes `since` AND `after` fields)
2. Call `fetchPage()` once (not in a loop)
3. If `nextAfter != ""`: return `LastPage: false` with cursor containing both `since` and `after`
4. If `nextAfter == ""`: return `LastPage: true` with cursor containing updated `since` (fetchedAt), no `after`

Update the Cursor struct:
```go
type Cursor struct {
    Since string `json:"since,omitempty"`
    After string `json:"after,omitempty"` // Link header pagination cursor
}
```

The key change in `Fetch()`:
```go
func (a *Adapter) Fetch(ctx context.Context, cursorJSON json.RawMessage) (*feed.FetchResult, error) {
    // ... parse cursor, compute sinceStr ...

    if err := a.rateLimiter.Wait(ctx); err != nil {
        return nil, fmt.Errorf("ghsa: rate limit: %w", err)
    }

    page, nextAfter, err := a.fetchPage(ctx, sinceStr, cur.After)
    if err != nil {
        return nil, err
    }

    fetchedAt := time.Now().UTC()
    var nextCursor Cursor
    var lastPage bool

    if nextAfter != "" {
        // More pages remain — carry the after cursor and the original since.
        nextCursor = Cursor{Since: cur.Since, After: nextAfter}
        lastPage = false
    } else {
        // Final page — advance since to fetchedAt, clear after.
        nextCursor = Cursor{Since: fetchedAt.Format(time.RFC3339)}
        lastPage = true
    }

    nextCursorJSON, err := json.Marshal(nextCursor)
    if err != nil {
        return nil, fmt.Errorf("ghsa: marshal cursor: %w", err)
    }

    return &feed.FetchResult{
        Patches:    page,
        SourceMeta: feed.SourceMeta{SourceName: SourceName, FetchedAt: fetchedAt},
        NextCursor: nextCursorJSON,
        LastPage:   lastPage,
    }, nil
}
```

**Step 3: Incorporate streaming JSON error handling (from Task 7)**

When rewriting `fetchPage`, apply the same streaming JSON error pattern from Task 7 inside the `dec.More()` loop: break on `json.SyntaxError`, continue on type errors. See Task 7 Step 2 for the exact pattern.

**Step 4: Update tests to verify multi-page behavior**

- Test first page returns `LastPage: false` with `After` in cursor
- Test last page (no Link header) returns `LastPage: true` with updated `Since`
- Test cursor round-trip: unmarshal returned cursor and verify fields

**Step 5: Run tests — expect PASS**

**Step 6: Commit**

```
refactor: GHSA adapter returns one page per Fetch for crash recovery
```

---

## Task 9: Add size limit to DownloadToTemp (D2)

**Files:**
- Modify: `internal/feed/util.go:157` (add `io.LimitReader`)

**Step 1: Write failing test**

Test that `DownloadToTemp` with a response larger than the limit returns an error. Use `httptest.Server` returning a body slightly larger than a test-friendly limit. Since `MaxDownloadSize` is a package variable (not a constant), override it in the test:

```go
func TestDownloadToTemp_SizeLimit(t *testing.T) {
    orig := MaxDownloadSize
    MaxDownloadSize = 1024 // 1 KiB for testing
    t.Cleanup(func() { MaxDownloadSize = orig })

    ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write(make([]byte, 2048)) // 2 KiB — exceeds limit
    }))
    defer ts.Close()

    _, err := DownloadToTemp(context.Background(), http.DefaultClient, ts.URL, "test")
    if err == nil {
        t.Fatal("expected error for oversized response")
    }
    if !strings.Contains(err.Error(), "exceeds") {
        t.Errorf("unexpected error: %v", err)
    }
}
```

**Step 2: Implement**

Use a package-level variable (not a constant) so tests can override it:

```go
// MaxDownloadSize is the limit for DownloadToTemp. Package-level var for testability.
var MaxDownloadSize int64 = 5 << 30 // 5 GiB

// In DownloadToTemp, change:
// io.Copy(f, resp.Body)
// To:
limited := io.LimitReader(resp.Body, MaxDownloadSize)
n, err := io.Copy(f, limited)
if err != nil {
    // ... cleanup ...
}
if n >= MaxDownloadSize {
    _ = f.Close()
    _ = os.Remove(f.Name())
    return nil, fmt.Errorf("feed: download %s: response exceeds %d byte limit", url, MaxDownloadSize)
}
```

**Step 3: Run test — expect PASS**

**Step 4: Commit**

```
fix: add 5GB size limit to DownloadToTemp
```

---

## Task 10: Add scheduler Prometheus metrics (D4)

**Files:**
- Modify: `internal/ingest/scheduler.go` (add counter registrations and increments)
- Test: `internal/ingest/scheduler_test.go` (verify counters increment)

**Step 1: Write failing test**

Test that after a scheduler tick, the `cvert_feed_jobs_enqueued_total` counter has incremented. Use `github.com/prometheus/client_golang/prometheus/testutil` to read counter values:

```go
import "github.com/prometheus/client_golang/prometheus/testutil"

// After triggering a scheduler tick:
val := testutil.ToFloat64(feedJobsEnqueued.WithLabelValues("nvd"))
if val != 1 {
    t.Errorf("expected 1 enqueued job, got %v", val)
}
```

Note: this is the first Prometheus metric registration in the codebase. You'll need to add `github.com/prometheus/client_golang` to the import (it's already a dependency in `go.mod` for the `/metrics` endpoint).

**Step 2: Implement**

Add to scheduler.go (use `promauto` to avoid `init()` + `MustRegister` ceremony):

```go
import "github.com/prometheus/client_golang/prometheus/promauto"

var (
    feedJobsEnqueued = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "cvert_feed_jobs_enqueued_total",
        Help: "Total feed jobs enqueued by the scheduler.",
    }, []string{"feed"})

    feedJobsSkipped = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "cvert_feed_jobs_skipped_total",
        Help: "Total feed jobs skipped by the scheduler.",
    }, []string{"feed", "reason"})
)
```

`promauto` auto-registers with the default registry and won't panic on duplicate registration in tests.

In `maybeEnqueue`: increment `feedJobsEnqueued` on enqueue, `feedJobsSkipped` (with reason label: "backoff", "not_due", "already_pending") on skip.

**Step 3: Run tests — expect PASS**

**Step 4: Commit**

```
feat: add Prometheus metrics for feed scheduler
```

---

## Task 11: Show all known feeds on first boot (D5)

**Files:**
- Modify: `internal/api/feeds.go` (listFeedsHandler — merge known feeds with DB state)

**Step 1: Write failing test**

Test that `GET /admin/feeds` returns entries for all known feeds (from `ingest.KnownFeeds`) even when `feed_sync_state` has no rows. Currently returns `{"feeds": []}`.

**Step 2: Implement**

In `listFeedsHandler`, after fetching DB states, create a map of feed_name → state. Then iterate `ingest.KnownFeeds` and build the response, using DB state where available and zero-valued `FeedStatusEntry` (with "Never Synced" equivalent) where not.

```go
stateMap := make(map[string]store.FeedSyncState, len(states))
for _, s := range states {
    stateMap[s.FeedName] = s
}

entries := make([]FeedStatusEntry, 0, len(ingest.KnownFeeds))
for _, feedName := range ingest.KnownFeeds {
    if s, ok := stateMap[feedName]; ok {
        logs, err := srv.store.ListRecentFeedFetchLogs(ctx, feedName, 5)
        if err != nil {
            slog.Error("list feed fetch logs", "feed", feedName, "error", err)
            http.Error(w, "internal error", http.StatusInternalServerError)
            return
        }
        entries = append(entries, feedStatusFromState(s, logs))
    } else {
        entries = append(entries, FeedStatusEntry{
            FeedName:   feedName,
            RecentLogs: []FeedLogEntry{},
        })
    }
}
```

**Step 3: Run tests — expect PASS**

Also update frontend test mock data expectations if needed.

**Step 4: Commit**

```
fix: show all known feeds in admin dashboard, not just synced ones
```

---

## Task 12: EPSS adapter — skip poison rows instead of blocking entire feed (D8)

**Files:**
- Modify: `internal/feed/epss/adapter.go:219-221` (log + continue instead of hard error)
- Test: `internal/feed/epss/adapter_test.go`

**Step 1: Write failing test**

Test that when `applyRow` returns an error for one CVE ID, the adapter continues processing remaining rows and returns success (not the error). Currently the adapter returns the error, blocking the entire feed.

**Step 2: Implement**

```go
// Before:
if err := applyRow(ctx, db, cveID, score, asOfDate); err != nil {
    return nil, fmt.Errorf("epss: apply row %q: %w", cveID, err)
}

// After:
if err := applyRow(ctx, db, cveID, score, asOfDate); err != nil {
    slog.WarnContext(ctx, "epss: skipping row with DB error",
        "cve_id", cveID, "error", err)
    continue
}
```

**Step 3: Run test — expect PASS**

**Step 4: Commit**

```
fix: EPSS adapter skips poison rows instead of blocking entire feed
```

---

## Task 13: Per-page cursor persistence in handler (D1 mitigation)

**Files:**
- Modify: `internal/ingest/handler.go` (persist cursor after each page, not just at end)

**Step 1: Write failing test**

Test that after processing page 1 of a 2-page feed where page 2 fails, the cursor from page 1 is persisted in `feed_sync_state`. Currently the cursor is only persisted at the end (success or error), but the error path persists `lastSuccessfulCursor` which is the cursor *before* the failed page, not after the last *successful* page.

Actually, looking at the code again: `lastSuccessfulCursor` IS updated after each successful page (line 101-103). The error-path sync state write (line 127-135) uses `lastSuccessfulCursor`. So the cursor IS persisted on failure. The gap is only if the sync state write itself fails (B2, now fixed in Task 2).

**Revised approach:** With B2 fixed, the remaining D1 risk is process crash between last merge and sync state write. To mitigate: persist `lastSuccessfulCursor` to the DB after each fully-processed page inside the pagination loop.

Add inside the pagination loop, after the `lastSuccessfulCursor` update (after the line `lastSuccessfulCursor = result.NextCursor`). Note: the `now` variable is declared AFTER the loop (at `now := time.Now()` around line 121), so use `time.Now()` directly here:

```go
// Persist cursor progress after each page for crash recovery.
pageNow := time.Now()
if syncErr := st.UpsertFeedSyncState(ctx, store.FeedSyncState{
    FeedName:      p.FeedName,
    CursorJSON:    lastSuccessfulCursor,
    LastSuccessAt: prevLastSuccess, // don't update until final success
    LastAttemptAt: &pageNow,
}); syncErr != nil {
    slog.Error("mid-pagination cursor persist failed",
        "feed", p.FeedName, "error", syncErr)
    // Don't abort — the cursor will be persisted at end of loop.
}
```

This is a best-effort optimization: if the mid-page persist fails, we continue and try at the end. The final persist (Task 2) will return an error on failure.

**Step 2: Write a test**

Test with a 2-page adapter where the process completes successfully. After the handler runs, read `feed_sync_state` and verify the cursor matches the final page's cursor (this confirms mid-page persistence didn't corrupt the final state). This is a regression test — the mid-page persist is best-effort and doesn't change the final outcome.

Capture and validate the `slog.Error` output if mid-page persist fails, per the pristine test output pattern.

**Step 3: Run tests — expect PASS**

**Step 4: Commit**

```
fix: persist cursor after each page for crash recovery
```

---

## Task 14: Update expectedSchemaVersion for new migrations

After Tasks 4 and 5 add migrations 000030 and 000031, update:

```go
const expectedSchemaVersion = 31
```

**Commit:**

```
chore: update expectedSchemaVersion to 31
```

---

## Task 15: Full test suite + lint

**Step 1:** Run full Go test suite: `go -C .worktrees/feed-wiring test ./... -count=1`
**Step 2:** Run linter: `cd .worktrees/feed-wiring && golangci-lint run`
**Step 3:** Run frontend tests: `cd .worktrees/feed-wiring/web && npx vitest run`
**Step 4:** Fix any failures.
**Step 5:** Commit any fixes.

---

## Task 16: Final review and branch finish

Use `superpowers:finishing-a-development-branch` to wrap up.
