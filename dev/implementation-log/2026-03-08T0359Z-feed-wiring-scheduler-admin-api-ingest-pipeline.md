# Feed Wiring — Scheduler, Admin API, Ingest Pipeline

> **Date:** 2026-03-06 to 2026-03-07
> **Commits:** `9499ef2`..`d540e85` on `dev` (PR #8)

## What was built

| Feature | Files | Description |
|---|---|---|
| Feed ingest handler | `internal/ingest/handler.go` | Generic worker handler: deserializes feed name, creates adapter via factory, paginated fetch loop with merge, cursor persistence per page for crash recovery. Exponential backoff |
| EPSS ingest handler | `internal/ingest/epss.go` | Separate handler for EPSS (uses `Apply()` not `Fetch()`). Same sync state/fetch log tracking |
| Adapter factory | `internal/ingest/feeds.go` | `NewAdapter` factory mapping feed names to concrete adapters. `KnownFeeds` canonical list |
| Feed scheduler | `internal/ingest/scheduler.go` | Periodic goroutine checking timing + backoff, enqueues jobs. Prometheus counters for enqueued/skipped |
| Admin feeds API | `internal/api/feeds.go` | `GET /api/v1/admin/feeds` (status + logs), `POST /api/v1/admin/feeds/{feed}/trigger` (manual re-run) |
| Site admin middleware | `internal/api/middleware_site_admin.go` | `RequireSiteAdmin()` — checks `is_site_admin` column. Gates admin endpoints |
| Site admin migration | `migrations/000030_add_site_admin.{up,down}.sql` | `is_site_admin BOOLEAN DEFAULT false` with `CREATE INDEX CONCURRENTLY` |
| Feed state store | `internal/store/feed.go` | Sync state CRUD + fetch log insertion. `withBypassTx` (no RLS for global feed state) |
| Shared feed utilities | `internal/feed/util.go` | Extracted `DownloadToTemp` (5GB limit), `CloneStrings`, `StripNullBytes`, `DrainBody`, `DoRequest`, `ReadResponseBody` |
| Feed status dashboard | `web/src/views/FeedStatusView.vue` | Live dashboard showing all feeds with sync state and recent fetch logs. Replaced placeholder |
| EPSS poison row handling | `internal/feed/epss/adapter.go` | Skips unparseable rows with warning log instead of aborting entire feed |
| GHSA pagination refactor | `internal/feed/ghsa/adapter.go` | Returns one page per `Fetch()` for crash recovery compatibility |

## Key implementation decisions

- **Per-page cursor persistence** — cursor state persisted after every successful page. Process crash resumes from last completed page, not the beginning. Drove the GHSA refactor
- **Job dedup via `ON CONFLICT DO NOTHING`** — eliminates TOCTOU race between scheduler and admin trigger
- **Site admin as boolean column** — YAGNI for now. Admin feed endpoints are the only consumer
- **Admin dashboard shows all known feeds** — newly registered feeds appear immediately even before first run
- **`backoffDuration` guards negative failures** — `max(failures, 0)` prevents panic from `1 << negative`

## Bug hunt findings (all fixed)

- `expectedSchemaVersion` stale (startup always warned)
- `InsertFeedFetchLog` discarded actual timestamps (used `now()` default)
- Sync state errors silently swallowed
- NVD adapter cursor regression (data race)
- EPSS blocked on malformed CSV rows
- `DownloadToTemp` had no size limit (OOM risk)
- GHSA fetched all pages internally, defeating crash recovery
- `backoffDuration` panicked on negative failure count

## Tests added

| Test file | Coverage |
|---|---|
| `internal/ingest/handler_test.go` | Success path, merge errors, cursor persistence, backoff panic guard |
| `internal/ingest/scheduler_test.go` | Interval scheduling, backoff skip, Prometheus counters, dedup |
| `internal/ingest/epss_test.go` | Success/error paths, sync state error propagation |
| `internal/api/feeds_test.go` | GET status, POST trigger, site admin gate, dedup |
| `internal/api/middleware_site_admin_test.go` | Admin/non-admin/missing-user/DB-error scenarios |
| `internal/store/feed_test.go` | Upsert idempotency, timestamp persistence |
| `internal/feed/util_test.go` | `DownloadToTemp` (5GB limit), `DoRequest`, `ReadResponseBody` |

## Quality checks

- 3 rounds of code review + 3 bug hunt campaigns
- CI pipeline updated: frontend test/build jobs, golangci-lint v2 config migration, version pinning
- Lint clean (16 feed util issues resolved)
