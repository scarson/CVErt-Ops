# Project Health Review — CVErt Ops
**Date:** 2026-03-18 03:08
**Scope:** Full review (all dimensions)

---

## Critical Findings

### 1. Batch and EPSS evaluators load all candidate CVE IDs into memory without pagination
**Dimensions:** Architecture
**Evidence:** `internal/alert/evaluator.go` — `getCVEsModifiedSince` and `getCVEsEPSSUpdatedSince` execute `SELECT cve_id FROM cves WHERE date_modified_canonical > $1` without a LIMIT clause, scanning into an unbounded `[]string` slice. These IDs are then passed as a 250k-element `ANY()` clause.
**Problem:** After a restart where the batch cursor is stale or zero, `getCVEsModifiedSince` returns every non-rejected CVE. With 250k+ CVEs, the unbounded slice causes OOM, and the massive `ANY()` clause makes Postgres spend minutes planning. The activation scan correctly paginates in 1000-row batches, but the batch and EPSS paths do not.
**Risk:** First batch evaluation after a fresh install or extended outage OOM-kills the worker or deadlocks Postgres query planning. Production reliability issue that manifests exactly when the system needs to catch up.
**Suggested approach:** Paginate candidate IDs in batches (e.g., 1000) using the same pattern as the activation scan. Process each batch through the rule evaluation loop before fetching the next.

---

## Major Findings

### 2. Delivery worker shutdown not awaited — notifications lost during graceful shutdown
**Dimensions:** Ops Readiness
**Evidence:** `cmd/cvert-ops/main.go:261` (serve) and `:446` (worker) — delivery worker started as fire-and-forget goroutine. After `ctx.Done()`, the function proceeds to `srv.Shutdown()` and returns. `defer db.Close()` may close the pool while in-flight deliveries (using `context.WithoutCancel`) are still executing.
**Problem:** In-flight webhook/email deliveries are interrupted when the DB pool closes, leaving deliveries in "processing" state with no recovery until the stuck-delivery reset timer fires on next startup.
**Risk:** Notifications silently lost during graceful shutdown. Users miss critical vulnerability alerts.
**Suggested approach:** Capture the delivery worker goroutine's done channel and wait for it (with a deadline) before closing the DB pool, in both serve and worker modes.

### 3. Missing API key query string rejection middleware — PLAN.md §16 requirement
**Dimensions:** API Design
**Evidence:** PLAN.md §16 requires returning 400 if a request includes an API key in any query parameter. Grep across `internal/api/` returns zero results for any such middleware.
**Problem:** API keys in query strings are logged by every proxy, CDN, browser history, and Referer headers. This is a documented security requirement that is not implemented.
**Risk:** API key leakage via access logs, browser history, or Referer headers.
**Suggested approach:** Add middleware early in the chain that scans query parameters for common API key names and returns 400.

### 4. Security event writer spawns unbounded goroutines with no timeout
**Dimensions:** Ops Readiness
**Evidence:** `internal/secure/writer.go:71-107` — each `Write` call spawns a goroutine with `context.WithoutCancel`. No concurrency limit, no context timeout. `Stop()` blocks on `wg.Wait()` indefinitely.
**Problem:** Under a brute-force attack with a degraded database, goroutines pile up (each holding `wg.Add(1)`). `Stop()` hangs on shutdown if any goroutine is stuck on a slow query.
**Risk:** Process hangs during shutdown. Under heavy load with degraded DB, unbounded goroutine growth leads to OOM.
**Suggested approach:** Add a semaphore (buffered channel) to bound concurrent writes, and add a context timeout to each write goroutine.

### 5. Metrics port not exposed in Dockerfile or production compose
**Dimensions:** Ops Readiness
**Evidence:** `docker/Dockerfile:39` only has `EXPOSE 8080`. The metrics server listens on `:9090`. Neither `compose.yml` nor `compose.prod.yml` map port 9090.
**Problem:** Prometheus cannot scrape the metrics endpoint. All carefully implemented metrics are invisible to monitoring.
**Risk:** Operators deploying with provided compose files get zero Prometheus observability.
**Suggested approach:** Add `EXPOSE 9090` to Dockerfile and map the metrics port in compose files (internal network only for production).

### 6. No container healthcheck for production app service
**Dimensions:** Ops Readiness
**Evidence:** `docker/compose.prod.yml:83-84` — "No healthcheck — distroless has no shell/curl." No health check binary installed.
**Problem:** Docker cannot detect a hung or unhealthy container. `restart: unless-stopped` only triggers on process exit, not on stuck processes. `/healthz` and `/readyz` endpoints exist but nothing calls them.
**Risk:** A deadlocked or pool-exhausted process runs indefinitely without restart.
**Suggested approach:** Add a statically-linked health check binary to the distroless image, or use Docker's `wget`-less healthcheck with a tiny Go binary that calls `/healthz`.

### 7. Dual HTTP framework (huma vs chi) creates inconsistent API surface
**Dimensions:** Code Quality, Architecture, API Design
**Evidence:** CVE routes use `huma.Register` with typed structs. All other routes (112+ handlers) use raw chi `http.HandlerFunc`. A separate 1734-line `openapi_spec.go` manually duplicates type definitions. Error responses use different Content-Types (`application/json` vs `application/problem+json`) and different envelope shapes.
**Problem:** Two handler paradigms with different validation, error formatting, and documentation strategies. The spec file can silently drift from handler implementations. API consumers must accommodate multiple error formats.
**Risk:** Input validation gaps in chi handlers. OpenAPI spec drift. Frontend error handling must special-case different error shapes.
**Suggested approach:** This is a large migration — incremental conversion of chi handlers to huma would unify the surface. Not urgent but should be planned.

### 8. Alert evaluator bypasses store abstraction with raw SQL and duplicated transaction management
**Dimensions:** Code Quality, Architecture, Test Quality
**Evidence:** `internal/alert/evaluator.go` holds its own `*sql.DB` reference and executes raw SQL directly. It has its own `bypassTx` method (`:544-562`) that duplicates `store.withBypassRawTx` but lacks panic recovery. Test seeding (`evaluator_test.go:67-104`) inserts via raw SQL with fake `material_hash` strings, bypassing the merge pipeline.
**Problem:** The evaluator is a second data access layer parallel to `internal/store`. Schema changes require updates in two places. Tests use synthetic data that diverges from production data shape.
**Risk:** Missing panic recovery could leave a transaction open. Schema evolution misses the evaluator's queries. Tests pass with fake data while production queries that join child tables fail.
**Suggested approach:** Move evaluator queries into the store layer (or a dedicated evaluator store interface). Use merge pipeline for test data seeding.

### 9. serve/worker command initialization duplicated ~80%
**Dimensions:** Architecture, Ops Readiness
**Evidence:** `cmd/cvert-ops/main.go:105-351` (runServe) and `:363-495` (runWorker) share nearly identical initialization: config loading, pool creation, metrics registration, feed config, evaluator setup, notification wiring, feed scheduler.
**Problem:** Any change to worker wiring must be made in two places. The delivery worker shutdown bug exists identically in both paths precisely because of this duplication. The paths have already diverged (runServe sets up AuditWriter, runWorker does not).
**Risk:** Bugs fixed in one path missed in the other. Silent behavioral divergence between serve and worker modes.
**Suggested approach:** Extract shared initialization into a common function that returns configured components.

### 10. No job queue depth metric
**Dimensions:** Ops Readiness
**Evidence:** `internal/metrics/worker.go` defines claimed/completed counters but no gauge for pending jobs. No `queue_depth` metric exists anywhere.
**Problem:** Operators cannot answer "how far behind is the system?" without querying the database directly.
**Risk:** Silent backlog growth undetected until users notice stale data or missing alerts.
**Suggested approach:** Add a Prometheus gauge that reports pending job count, updated on each poll cycle.

### 11. JWT parse functions are near-identical copies — 4x duplication of security-critical code
**Dimensions:** Code Quality
**Evidence:** `internal/auth/jwt.go` — `ParseAccessToken` (`:50-78`), `ParseRefreshToken` (`:118-146`), `ParsePendingToken` (`:190-218`), `ParseEnrollmentToken` (`:253-281`). All four implement the same dual-key rotation logic.
**Problem:** ~120 lines of copy-pasted logic in a security-critical code path. Any bug fix or behavioral change must be applied four times.
**Risk:** A security-relevant change applied to some parse functions but missed in others.
**Suggested approach:** Extract a generic `parseToken[T Claims]` helper parameterized by claims type and error prefix.

### 12. Per-org rate limiter missing Retry-After header on 429
**Dimensions:** API Design
**Evidence:** `internal/api/middleware_tier.go:70` returns 429 with no Retry-After header. The IP rate limiter in `ratelimit.go:89` correctly sets `Retry-After: 60`.
**Problem:** PLAN.md §16.1 requires 429 responses include Retry-After. Inconsistent between the two rate limiters.
**Risk:** Clients cannot implement proper backoff from org rate limits.
**Suggested approach:** Add `Retry-After` header to the org rate limiter's 429 response.

### 13. No feed adapter-to-store integration tests
**Dimensions:** Test Quality
**Evidence:** Adapter tests parse JSON into `CanonicalPatch` structs. Pipeline tests construct patches manually. No test verifies the full path: `adapter.Fetch()` → `CanonicalPatch` → `merge.Ingest()` → database.
**Problem:** A field mapping mistake in any adapter (e.g., swapping CVSSv3/v4 vectors, losing CWE IDs) would be invisible to both test suites.
**Risk:** Incorrect field mappings in feed adapters silently produce wrong data in the CVE corpus.
**Suggested approach:** Add integration tests per adapter that feed canned JSON through the full pipeline and verify database state.

### 14. No circuit breaker or health-aware retry on outbound feed HTTP
**Dimensions:** Architecture
**Evidence:** Feed adapters receive an `*http.Client` with a 5-minute timeout. No circuit breaker, no health tracking per upstream.
**Problem:** When an upstream feed is degraded, the system consumes full 5-minute timeouts with no fast-fail. Worker pool slots fill with hanging HTTP calls.
**Risk:** NVD outage blocks all feed processing by consuming all worker concurrency slots.
**Suggested approach:** Add per-feed circuit breaker that trips after N consecutive failures and fast-fails for a backoff period.

### 15. No graceful degradation when Postgres is slow or unavailable at runtime
**Dimensions:** Architecture
**Evidence:** No load shedding. When Postgres is slow, all components hammer it with timing-out queries. pgxpool has 25-connection limit but no queue depth limit.
**Problem:** Temporary DB degradation causes blocked goroutines to accumulate. Memory grows until OOM-kill.
**Risk:** Transient Postgres issues cascade into full process crash with no graceful recovery.
**Suggested approach:** Add connection acquisition timeout and request queue depth limits to shed load during DB pressure.

### 16. import-bulk CLI subcommand is a stub
**Dimensions:** Architecture
**Evidence:** `cmd/cvert-ops/main.go:678` logs "import-bulk not yet implemented." PLAN.md §3.3 describes this as critical for initial data population.
**Problem:** New deployments rely solely on API polling for initial data. The CVE corpus takes hours to days to populate.
**Risk:** New deployments have empty CVE corpus for an extended period. Users see zero alerts.
**Suggested approach:** Implement bulk import from NVD JSON feeds file as planned.

### 17. Alert evaluation paths duplicated 3x
**Dimensions:** Code Quality
**Evidence:** `internal/alert/evaluator.go` — `EvaluateRealtime` (`:88-120`), `EvaluateBatch` (`:124-169`), `EvaluateEPSS` (`:173-218`). Batch and EPSS are nearly line-for-line identical.
**Problem:** Behavioral changes must be applied in three places. Batch and EPSS share the same cursor-iterate-metrics pattern.
**Risk:** Inconsistency when the evaluation loop is modified.
**Suggested approach:** Extract a shared `evaluateBatchPath` helper for the batch/EPSS common pattern.

### 18. store.UpsertDelivery hand-rolls bypass transaction — missing panic recovery
**Dimensions:** Code Quality
**Evidence:** `internal/store/notification_delivery.go:39-52` — manually opens tx, sets bypass_rls, executes SQL, commits. Bypasses `withBypassRawTx` which includes panic-recovery defer.
**Problem:** A panic inside the raw SQL path would leak the transaction without rollback.
**Risk:** Leaked transaction on panic (unlikely but real correctness gap).
**Suggested approach:** Convert to use `withBypassRawTx`.

### 19. Inconsistent pagination — 6 list endpoints have no pagination
**Dimensions:** API Design
**Evidence:** `listChannelsHandler`, `listMembersHandler`, `listInvitationsHandler`, `listAPIKeysHandler`, `listReportsHandler`, `listFeedsHandler` — all return unbounded results with no limit or cursor.
**Problem:** While some collections are naturally small, channels, API keys, and reports can grow. Inconsistent API surface.
**Risk:** Unbounded response payloads. Inconsistent consumer expectations.
**Suggested approach:** Add pagination to endpoints where collections can grow (channels, API keys, reports). Leave feeds as-is (fixed small set).

### 20. CVE endpoints are fully unauthenticated
**Dimensions:** API Design
**Evidence:** `server.go:234` — `registerCVERoutes` called without auth middleware. Code comment says "auth middleware added in Phase 2."
**Problem:** The entire CVE corpus is publicly accessible. Only IP rate limiting (10 req/min) protects it.
**Risk:** If public access is unintentional, full CVE corpus exposed. Even if intentional, vulnerable to scraping.
**Suggested approach:** Design decision — determine if CVE endpoints should require auth or remain public. If public, consider higher IP rate limits for enumeration protection.

### 21. Webhook delivery tests bypass safeurl client entirely
**Dimensions:** Test Quality
**Evidence:** `internal/notify/webhook_test.go:23-31` and `worker_test.go:23-29` use plain `http.Client`. The production safeurl client is never exercised in delivery tests.
**Problem:** Bugs in safeurl integration (configuration, timeout, redirect policy) would not be caught.
**Risk:** Production webhook delivery uses a different HTTP client than all tests exercise.
**Suggested approach:** Add at least one integration test that uses the real safeurl client against an external (non-loopback) test server.

### 22. No timing-attack test for API key comparison
**Dimensions:** Test Quality
**Evidence:** `internal/auth/apikey_test.go` covers generation/hashing/uniqueness only. No test verifies `subtle.ConstantTimeCompare` is used.
**Problem:** A regression from `subtle.ConstantTimeCompare` to `==` would pass all existing tests.
**Risk:** Timing side-channel attack on API key validation.
**Suggested approach:** Add a code-level test (grep or AST check) that verifies `subtle.ConstantTimeCompare` is used in the comparison path, or add a test that asserts the comparison function is constant-time.

### 23. TestOrgTx_CommitsOnSuccess does not verify commit persistence
**Dimensions:** Test Quality
**Evidence:** `internal/store/store_test.go:80-98` — runs `SELECT 1` inside OrgTx and asserts no error. Never writes data or verifies persistence.
**Problem:** The commit path could silently call Rollback instead of Commit and this test would still pass.
**Risk:** OrgTx commit correctness is untested.
**Suggested approach:** Write a row inside OrgTx, return, then verify the row persists in a separate query.

---

## Minor Findings

### Observability Gaps (Ops Readiness)
- **No notification delivery queue depth metric** — pending deliveries invisible to monitoring
- **Retention cleanup has no Prometheus metrics** — table growth undetected if cleanup fails
- **Standalone worker mode has no readiness endpoint** — hung worker undetected by orchestrator

### Configuration Validation (Ops Readiness)
- **REGISTRATION_MODE not validated at startup** — typo silently changes behavior
- **DB_QUERY_EXEC_MODE not validated** — typo breaks PgBouncer compatibility
- **SMTP defaults point to Mailpit in production** — email silently broken if not configured
- **init.sql uses hardcoded dev password** — credential gap in provided compose files

### Shutdown & Lifecycle (Ops Readiness)
- **Auto-migrate advisory lock blocks indefinitely** — startup hangs if prior session alive
- **Log level reload does not take effect** — config updated but logger not refreshed
- **Per-org semaphore map grows without bound** — minor leak in high-tenant deployments

### Resource Limits (Ops Readiness)
- **Feed client has no response body size limit** — malicious feed response causes OOM
- **Stale job threshold (5 min) < max job duration (10 min)** — long jobs prematurely reclaimed

### Code Quality
- **NullString conflates empty string with NULL** — `dbutil.NullString("")` returns `{Valid: false}`
- **ingest.Handler has 4 factory-function variants** — combinatorial explosion of optional features
- **applyNVDCVSS has 3 copy-pasted blocks** for v3.1/v3.0/v4.0 metric extraction
- **merge.Ingest is a 294-line God Function** with 10 sequential steps
- **Server struct has 20+ fields** — megastruct suggests HTTP layer does too much
- **Store methods wrap single reads in withBypassTx** — 3 extra DB round trips per auth check
- **time.Now() scattered throughout business logic** — makes time-dependent code untestable
- **isPermanentDeliveryError uses string matching** on error messages for SMTP code detection

### Architecture
- **internal/search/ directory is empty** — FTS logic scattered in store/handlers
- **Notification worker reimplements job processing** — separate event loop parallel to worker.Pool
- **merge.Store interface exposes DB() *sql.DB** — leaks database abstraction
- **Retention runner takes concrete *store.Store** — cannot be unit-tested without DB
- **Feed adapter factory uses switch statement** — adding adapters requires 3 locations
- **internal/report/ directory is empty** — digest reports in notify package
- **Slack channel type missing** — PLAN.md lists as MVP, not implemented

### API Design
- **Alert rules/events/watchlists have hardcoded page sizes** — no client override unlike other endpoints
- **Stale comment documents ?after= instead of ?cursor=** in alert events handler
- **Frontend uses raw fetch() for several endpoints** — bypasses typed client and refresh interceptor
- **createAlertRuleBody.Enabled is non-pointer bool** — zero-value creates draft silently
- **Admin retry delivery returns 200 vs org endpoint's 204** — inconsistent status codes
- **Admin bulk retry misuses `limit` parameter name** — means "max retries" not page size
- **No Cache-Control headers on any response** — stale caches, unnecessary backend load
- **Inconsistent 404 detail messages** — some include resource type, others generic
- **unbindChannelFromReport doesn't verify binding exists** — inconsistent with rule unbind
- **createChannelBody.Type defaults to webhook silently** — undocumented default
- **ListCVEsInput has undocumented query parameters** — cvss_min/max, epss_min/max invisible in OpenAPI
- **testChannelHandler returns 200 even on failure** — success:false in 200 body
- **password_change_required response bypasses writeProblem** — missing status field

### Test Quality
- **RuleCache test uses nil compiled rule** — tests cache mechanics but not real data
- **TestHashPasswordOWASPParameters coupled to exact parameter string** — brittle on updates
- **TestSend_DeniedHeaderStripped discards error** — test passes vacuously if Send fails
- **No concurrency tests for RuleCache** — thread safety only tested under production load
- **TestIngest_AdvisoryLockAcquired is redundant** — no verification beyond other Ingest tests
- **Store test helpers silently discard errors** — `org, _ := s.CreateOrg(...)` masks setup failures
- **TestBuildSafeClient only checks timeout** — doesn't verify redirect or MaxConnsPerHost
- **No EPSS two-statement pattern test** — staging insert for non-existent CVE untested
- **No pending-token-as-access-token rejection test** — MFA bypass potential untested

---

## Cross-Cutting Themes

### Theme 1: Alert Evaluator as a "Rogue Component"
Findings C1, M8, M17, and multiple minor findings all trace to the alert evaluator operating as a parallel system to the store layer. It has its own `*sql.DB`, its own transaction management, its own SQL queries, and its tests use raw SQL seeding. This is the highest-concentration area of risk in the codebase — unbounded memory, missing panic recovery, and test data that diverges from production.

### Theme 2: Dual Execution Paths (serve vs worker)
The ~80% initialization duplication between `runServe` and `runWorker` is the root cause of multiple findings. The delivery worker shutdown bug exists in both paths. The AuditWriter divergence shows drift has already begun. Any fix applied to one path must be manually replicated.

### Theme 3: Dual HTTP Framework Friction
The huma-vs-chi split creates cascading inconsistencies: different error formats, different validation approaches, a 1734-line manual OpenAPI spec, and frontend code that must accommodate multiple error shapes. This will compound with every new endpoint.

### Theme 4: Observability Gaps
The metrics infrastructure is carefully built but partially invisible: port not exposed in Docker, no queue depth gauges, no retention metrics, no delivery backlog metric. An operator would have the tools to monitor but no way to actually receive the data.

### Theme 5: Shutdown Safety
Three independent shutdown hazards: delivery worker not awaited (M2), security event writer blocks indefinitely (M4), and auto-migrate advisory lock (minor). Together they create a scenario where graceful shutdown is neither graceful nor complete.
