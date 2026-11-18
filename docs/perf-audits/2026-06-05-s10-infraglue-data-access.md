# S10 Platform/Infra Glue — Data-Access Lane
**Date:** 2026-06-05
**Slice:** S10 — binary init, config, crypto, doctor, metrics, server wiring, feeds/ingest admin handlers
**Lane:** data-access

## Scope examined

- `cmd/cvert-ops/main.go` — DB pool construction, startup queries, `newPool`
- `internal/config/config.go` — pool-sizing defaults
- `internal/api/readyz.go` — `/readyz` handler
- `internal/api/server.go` — handler wiring
- `internal/api/feeds.go` — feed status admin handler
- `internal/api/ingest.go` — inbound webhook handler
- `internal/api/admin_doctor.go` — doctor API handler
- `internal/api/contract.go`, `internal/api/context.go`, `internal/api/log_middleware.go`, `internal/api/middleware_cache.go`, `internal/api/metrics_middleware.go`
- `internal/doctor/doctor.go`, `internal/doctor/checks.go`
- `internal/metrics/db.go` — DB pool Prometheus collector
- `internal/dbutil/null.go`, `internal/log/context.go`

---

## Findings

### MAJOR — `/readyz` issues two DB round-trips on every probe with no caching

**Location:** `internal/api/readyz.go:29-63`

**Problem:** Every call to `/readyz` executes two sequential database operations:
1. `db.Ping()` — a round-trip to the Postgres server (sends a trivial query internally, waits for response)
2. `db.QueryRow(…"SELECT version, dirty FROM schema_migrations …")` — a second full round-trip

In Kubernetes, `/readyz` is called by liveness/readiness probes at 10–30-second intervals by every probe configured on the pod. In a production multi-pod deployment (e.g. 3 replicas × 2 probes/min), that is ≥6 probe round-trips per minute hitting the pool purely to answer "are you ready?". Across 10 replicas this becomes 20 round-trips per minute just from readiness probing.

More critically, the migration version check answers a question that changes exactly once per deployment (on schema version update) and never reverts. Querying `schema_migrations` on every probe is equivalent to re-reading a config file on every HTTP request. The Ping check duplicates what the pool's internal health-check period already does.

Neither result is cached; the handler carries no `sync.Once`, `sync.Map`, or TTL-backed cache.

**Impact:** Every readiness probe consumes one pool connection for its duration (two sequential queries). Under aggressive probe scheduling or high-replica deployments this competes with API traffic for pool connections (default `DB_MAX_CONNS=25`). The migration check in particular is pure overhead: it cannot change between probes without a deployment event that restarts the process anyway.

**Confidence:** Strong-static

**Effort:** Localized — `readyzHandler` closure accepts and caches a migration-check result at construction time. The Ping check can be kept (it provides a live circuit-breaker signal) but the migration query should be replaced with a value captured once at startup (the `expectedSchemaVersion` guard already runs in `newPool` at startup).

**Verification plan:** The behavior change is: migration result is `"current"` always (captured once, read from memory). Pin the existing `readyz` integration test and confirm the DB interaction count drops from 2 to 1 per call. For the correctness guard: ensure the handler still returns 503 if the pool is down (Ping fails), which is the operationally meaningful signal.

---

### MINOR — `listFeedsHandler` issues N separate DB queries for fetch logs (one per feed)

**Location:** `internal/api/feeds.go:63-80`

**Problem:** The handler first calls `ListFeedSyncStates` (one query, returns all feed rows), then for each feed name in `AllFeedNames()` that has a state entry it calls `ListRecentFeedFetchLogs(ctx, feedName, 5)` — one query per feed. With 8 built-in feeds plus any registered generic feeds, this is 1 + N round-trips per request where N is the number of feeds with state rows.

```go
for _, feedName := range allFeeds {
    if s, ok := stateMap[feedName]; ok {
        logs, err := srv.store.ListRecentFeedFetchLogs(ctx, feedName, 5)
        // ...
    }
}
```

This is a textbook N+1. A single query (`SELECT ... FROM feed_fetch_log WHERE feed_name = ANY($1) ORDER BY feed_name, started_at DESC`) followed by application-side grouping, or a lateral join, would replace all N log queries with one.

The endpoint is admin-only and is not on a hot path — but it is called by admin dashboards that may poll (e.g., every few seconds to watch feed progress).

**Impact:** Reachability: admin-only, but a polling dashboard makes this reachable at 0.1–1 Hz. Per-occurrence cost: 1 + N round-trips (N=8 built-in, potentially more with generics). Each round-trip holds a pool connection for the query duration. At 1 Hz polling by 3 admins = 27 round-trips/second on a pool sized for application traffic.

**Confidence:** Strong-static

**Effort:** Contained — requires a new store method (or modified query) that returns logs for a set of feed names; the handler assembles the `FeedStatusEntry` slice by grouping client-side.

**Verification plan:** Add a store method taking `[]string` feed names and returning all matching log rows (up to 5 per feed). The correctness guard is the existing `listFeedsHandler` integration test confirming per-feed log association is preserved.

---

### MINOR — `RLSCheck` issues one `pg_class` query per org-scoped table (22 queries)

**Location:** `internal/doctor/checks.go:132-153`

**Problem:** `RLSCheck.Run` loops over `OrgScopedTables()` (22 tables as of the current list) and issues one `SELECT relrowsecurity FROM pg_class WHERE relname = $1` query per table:

```go
for _, table := range c.Tables {
    var enabled bool
    err := c.DB.QueryRow(ctx,
        "SELECT relrowsecurity FROM pg_class WHERE relname = $1",
        table,
    ).Scan(&enabled)
```

This is 22 sequential round-trips where a single `SELECT relname, relrowsecurity FROM pg_class WHERE relname = ANY($1::text[])` would serve the same result in one.

The doctor endpoint is called on demand (`GET /admin/doctor`) and from the CLI `cvert-ops doctor`. It is not a hot path. The finding is logged only because the N=22 pattern is fixable without any complexity cost, and the check runs inside the `/readyz`-adjacent admin surface that operators may poll post-deploy.

**Impact:** Low frequency (on-demand), but 22 sequential round-trips per invocation on a pool shared with API traffic. Each query holds a connection for the round-trip. Replacing with `ANY($1::text[])` reduces to 1 round-trip.

**Confidence:** Strong-static

**Effort:** Localized — replace the loop+single-query with one `ANY`-parameterized query and do the missing-table detection client-side.

**Verification plan:** The existing `doctor_test.go` cases must pass unchanged. Verify the resulting query appears once in pg_stat_statements (or via query logging) rather than 22 times per check run.

---

## Confirmed-cold items (examined, no finding)

- **DB pool config (`newPool`):** `MaxConns` (default 25), `MaxConnIdleTime` (default 5 min) are configurable and documented. `MaxConnLifetime` is unset — pgxpool defaults to no maximum lifetime, which is appropriate for PgBouncer transaction-mode where the backend handles connection recycling. No `MinConns` is set (correct: avoids pre-heating a pool that may never be needed on idle instances). No finding.

- **Startup advisory queries (`newPool`):** `SHOW max_connections` and `SELECT version FROM schema_migrations` are each issued once at startup, not on the request path. No finding.

- **`metrics.DBPoolCollector`:** `Collect` calls `pool.Stat()` which reads an in-memory atomic counter snapshot — no DB round-trip. Scrape-driven, bounded to Prometheus scrape interval. No finding.

- **Global middleware chain (no DB transactions):** The full middleware stack — security headers, CORS, RequestID, RealIP, `clientIPMiddleware`, `contextLoggerMiddleware`, `RequestSize`, `Recoverer`, `httpMetricsMiddleware`, `csrfProtect`, `noCacheMiddleware`, `rejectAPIKeyQueryParams` — none of these open a DB connection or transaction. The per-request DB footprint from middleware is zero. No finding.

- **`healthzHandler`:** Pure in-memory response, no DB. No finding.

- **`ingestHandler`:** Calls `merge.Ingest` per patch, which is the expected merge pipeline cost and is gated behind authentication, RBAC, and tier rate-limiting. No middleware-level DB overhead beyond the auth path. No finding.

- **`doctorHandler` on-demand invocation:** All checks that hit the DB (connectivity ping, migration query, role query, RLS queries, encryption sentinel query, feed query) run only when `GET /admin/doctor` is called. The endpoint is admin-gated and not polled by infrastructure. The DB cost is acceptable at this frequency; only the per-table RLS loop is flagged above.

- **`FeedCheck`:** Single `SELECT ... FROM feed_sync_state WHERE consecutive_failures >= $1` — one round-trip. No finding.

---

## Suspected Bugs (for follow-up)

None observed during this lane's reading.
