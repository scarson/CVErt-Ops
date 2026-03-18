# Full Health Review — Validated Findings

**Date:** 2026-03-18
**Scope:** Full review across all dimensions
**Source:** Project health review (5-dimension adversarial)

---

## Confirmed Issues

### I1. Batch and EPSS evaluators load all candidate CVE IDs into memory without pagination
**Severity:** CRITICAL
**Dimensions:** Architecture
**Location:** `internal/alert/evaluator.go:566-601` — `getCVEsModifiedSince` and `getCVEsEPSSUpdatedSince`
**Evidence:** Both functions execute `SELECT cve_id FROM cves WHERE ...` without a LIMIT clause, scanning into an unbounded `[]string`. When the cursor is zero (first run or stale), `getCVEsModifiedSince` returns every non-rejected CVE (~250k+). These IDs are then passed to `evaluateRule` which uses `ANY($1)` with the entire slice. The activation scan (`getCVEsBatch` at :606-623) correctly paginates in 1000-row batches — the pattern for doing it right is already in the codebase.
**Blast radius:** Localized fix in `evaluator.go` only. Need to add pagination loop around the batch/EPSS evaluation paths. No API changes. No migration needed.
**Fix approach:** Paginate candidate IDs using the same keyset pattern as `getCVEsBatch`. Process each page through the rule evaluation loop before fetching the next page.

### I2. Delivery worker shutdown not awaited — notifications lost during graceful shutdown
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `cmd/cvert-ops/main.go:261` (serve mode) and `:446` (worker mode)
**Evidence:** Both modes start the delivery worker as `go deliveryWorker.Start(ctx)` with no mechanism to await completion. After `ctx.Done()`, serve mode proceeds to `srv.Shutdown(shutdownCtx)` and returns. Worker mode proceeds to metrics shutdown and returns. In both cases, `defer db.Close()` (at :121 and :379 respectively) races against in-flight deliveries that use `context.WithoutCancel`. The delivery worker's `Start` method blocks internally on its own `wg.Wait()`, but the calling goroutine is never joined.
**Blast radius:** `cmd/cvert-ops/main.go` only. Need to capture a done channel from the delivery worker goroutine and wait for it before DB close. Both serve and worker modes affected (same root cause amplified by the serve/worker duplication).
**Fix approach:** Add a done channel or `sync.WaitGroup` to coordinate delivery worker shutdown completion before `db.Close()`. Apply to both `runServe` and `runWorker`.

### I3. Security event writer spawns unbounded goroutines with no timeout
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `internal/secure/writer.go:71-107`
**Evidence:** Each `Write` call spawns a goroutine with `context.WithoutCancel(ctx)`. No concurrency limit (semaphore or worker pool). No timeout on the detached context. `Stop()` at :112-114 calls `w.wg.Wait()` with no deadline — if any goroutine is stuck on a slow DB insert, shutdown blocks indefinitely. Under a brute-force attack where the rate limiter allows events through (10/min per key, but many distinct keys), goroutines accumulate.
**Blast radius:** `internal/secure/writer.go` only. Add a semaphore and per-write timeout.
**Fix approach:** Add a buffered channel as a concurrency limiter (e.g., 50). Add `context.WithTimeout` to each write goroutine (e.g., 10s). Consider a `Stop()` timeout that logs and proceeds if writes don't drain.

### I4. Metrics port not exposed in Dockerfile or production compose
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `docker/Dockerfile:39`, `docker/compose.prod.yml:18`
**Evidence:** Dockerfile only has `EXPOSE 8080`. The metrics server listens on `:9090` (default `METRICS_PORT`). compose.prod.yml line 18 comments mention "App metrics port (9090) on internal network only" but no port mapping is configured anywhere in the compose files.
**Blast radius:** Two files: Dockerfile and compose.prod.yml. Trivial fix.
**Fix approach:** Add `EXPOSE 9090` to Dockerfile. Add port mapping in compose.prod.yml on the internal network.

### I5. No container healthcheck for production app service
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `docker/compose.prod.yml:83-84`
**Evidence:** compose.prod.yml explicitly says "No healthcheck — distroless has no shell/curl." The `/healthz` and `/readyz` endpoints exist in the app but nothing in the container orchestration calls them. This was also flagged in the March 10 health review (C3) and remains unaddressed.
**Blast radius:** Dockerfile (add health binary) + compose.prod.yml (add healthcheck). Alternatively, compile a tiny Go binary that calls `/healthz` and include it in the distroless image.
**Fix approach:** Build a static Go healthcheck binary in the builder stage, copy it to the runtime image, add `HEALTHCHECK` directive.

### I6. Alert evaluator bypasses store abstraction with raw SQL and duplicated transaction management
**Severity:** MAJOR
**Dimensions:** Code Quality, Architecture, Test Quality
**Location:** `internal/alert/evaluator.go:544-562` (bypassTx), evaluator.go throughout (raw SQL), `internal/alert/evaluator_test.go:67-104` (raw SQL seeding)
**Evidence:** The evaluator holds its own `*sql.DB` and executes raw SQL queries directly. Its `bypassTx` method duplicates `store.withBypassRawTx` but omits the panic-recovery defer (compare store.go:78-83 which has `defer func() { if p := recover() ... }`). Tests seed CVE data via raw SQL with fake material_hash strings like `"hash-batch-1"`, bypassing the merge pipeline entirely.
**Blast radius:** Moderate — involves `internal/alert/evaluator.go` and its tests. Moving queries to a store interface would touch evaluator.go and add new store methods. Test changes to use merge pipeline for seeding would be more involved.
**Fix approach:** (1) Add panic recovery to evaluator.bypassTx immediately. (2) Longer-term: move evaluator queries into a dedicated store interface. (3) Refactor evaluator tests to seed data through the merge pipeline.

### I7. JWT parse functions are near-identical copies — 4x duplication of security-critical code
**Severity:** MAJOR
**Dimensions:** Code Quality
**Location:** `internal/auth/jwt.go:50-78` (Access), `:118-146` (Refresh), `:190-218` (Pending), `:253-281` (Enrollment)
**Evidence:** All four parse functions implement identical dual-key rotation logic: try activeSecret → check for `ErrTokenSignatureInvalid` → retry with previousSecret. The bodies differ only in claims type and error prefix string. ~120 lines of copy-pasted code in a security-critical path.
**Blast radius:** `internal/auth/jwt.go` only. Extract a generic helper function.
**Fix approach:** Create a `parseToken[T jwt.Claims]` generic helper that encapsulates the dual-key rotation logic. Each public Parse function becomes a one-liner calling the generic helper with its specific claims type.

### I8. Per-org rate limiter missing Retry-After header on 429
**Severity:** MAJOR
**Dimensions:** API Design
**Location:** `internal/api/middleware_tier.go:70`
**Evidence:** The org rate limiter returns `writeProblem(w, http.StatusTooManyRequests, "rate limit exceeded")` with no `Retry-After` header. The IP rate limiter at `ratelimit.go:89` correctly sets `w.Header().Set("Retry-After", "60")`. The AI quota limiter also sets `Retry-After`. PLAN.md §16.1 states exceeded limits return 429 with Retry-After.
**Blast radius:** One line addition in `middleware_tier.go`.
**Fix approach:** Add `w.Header().Set("Retry-After", ...)` before the `writeProblem` call. Compute the value from the rate limiter's bucket state or use a fixed value.

### I9. serve/worker command initialization duplicated ~80%
**Severity:** MAJOR
**Dimensions:** Architecture, Ops Readiness
**Location:** `cmd/cvert-ops/main.go:105-351` (runServe) and `:363-495` (runWorker)
**Evidence:** Both functions duplicate: config loading, pool creation, metrics registration, feed config loading, alert cache/evaluator setup, notification worker creation, feed scheduler setup. The delivery worker shutdown bug (I2) exists identically in both paths because of this duplication. The paths have already diverged — runServe sets up AuditWriter, runWorker does not.
**Blast radius:** Large — refactoring main.go to extract shared initialization. All existing tests should still pass since behavior doesn't change.
**Fix approach:** Extract shared initialization into a common `buildApp()` function returning configured components. Serve and worker modes each add their specific wiring.

### I10. No job queue depth metric
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `internal/metrics/worker.go`
**Evidence:** Worker metrics include `claimed_total` and `completed_total` counters but no gauge for pending/queued jobs. An operator cannot determine backlog size from Prometheus alone.
**Blast radius:** Localized — add a gauge metric and update it in the worker poll loop.
**Fix approach:** Add a `GaugeVec` for pending job count. Update it after each poll cycle (e.g., report the count from `ClaimJobs` or a separate `SELECT count(*) FROM job_queue WHERE status = 'pending'`).

### I11. No feed adapter-to-store integration tests
**Severity:** MAJOR
**Dimensions:** Test Quality
**Location:** Pattern across `internal/feed/*/adapter_test.go` and `internal/merge/pipeline_integration_test.go`
**Evidence:** Feed adapter tests parse JSON into CanonicalPatch structs using httptest servers. Merge pipeline integration tests construct CanonicalPatch structs manually. No test verifies the full pipeline: adapter.Fetch() → CanonicalPatch → merge.Ingest() → database state. A field mapping error in any adapter would be invisible to both test suites.
**Blast radius:** New test files — one per adapter (or a shared integration test parameterized by adapter). Requires test DB.
**Fix approach:** Add integration tests that feed canned upstream JSON through the full adapter → merge → DB pipeline and verify the resulting database state.

### I12. Alert evaluation paths duplicated 3x
**Severity:** MAJOR
**Dimensions:** Code Quality
**Location:** `internal/alert/evaluator.go:88-120` (Realtime), `:124-169` (Batch), `:173-218` (EPSS)
**Evidence:** EvaluateBatch and EvaluateEPSS are nearly line-for-line identical — cursor read, candidate fetch, rule list, rule iteration with loadAndCompileRule + evaluateRule, metrics, cursor write. Only the cursor name, rule-listing method, and metrics label differ.
**Blast radius:** `evaluator.go` only. Extract common batch evaluation path.
**Fix approach:** Create an `evaluateBatchPath` helper parameterized by cursor name, candidate-fetch function, rule-list function, and metrics label.

### I13. store.UpsertDelivery hand-rolls bypass transaction — missing panic recovery
**Severity:** MAJOR
**Dimensions:** Code Quality
**Location:** `internal/store/notification_delivery.go:39-52`
**Evidence:** Manually opens tx, sets bypass_rls, executes SQL, commits. Bypasses `withBypassRawTx` which includes panic-recovery defer (store.go:78-83). The comment explains the reason (need raw tx on same connection as SET LOCAL), but `withBypassRawTx` does exactly this with panic recovery.
**Blast radius:** One function. Convert to use `withBypassRawTx`.
**Fix approach:** Replace the hand-rolled transaction with `s.withBypassRawTx(ctx, func(tx *sql.Tx) error { ... })`.

### I14. TestOrgTx_CommitsOnSuccess does not verify commit persistence
**Severity:** MAJOR
**Dimensions:** Test Quality
**Location:** `internal/store/store_test.go:80-98`
**Evidence:** The test opens an OrgTx, executes `SELECT 1`, and asserts no error. The comment says "Insert a row within OrgTx — it should persist after commit" but the code does not write or verify anything. The symmetric test `TestOrgTx_RollsBackOnError` properly verifies rollback.
**Blast radius:** One test function.
**Fix approach:** Write a row inside OrgTx, return successfully, then verify the row persists via a separate query.

### I15. Webhook delivery tests bypass safeurl client entirely
**Severity:** MAJOR
**Dimensions:** Test Quality
**Location:** `internal/notify/webhook_test.go:23-31`, `internal/notify/worker_test.go:23-29`
**Evidence:** All webhook delivery tests use plain `http.Client` because safeurl blocks 127.0.0.1 (httptest servers). The production safeurl client is never exercised in functional delivery tests.
**Blast radius:** Test changes only. May need an external test server or a configurable safeurl allowlist for tests.
**Fix approach:** Add at least one integration test that verifies the safeurl client configuration (redirect disabled, MaxConnsPerHost, timeout) by testing against a non-loopback address.

### I16. Stale job threshold (5 min) shorter than max job duration (10 min)
**Severity:** MAJOR
**Dimensions:** Ops Readiness
**Location:** `internal/worker/pool.go:34-39`
**Evidence:** `staleThreshold = 5 * time.Minute` and `maxJobDuration = 10 * time.Minute`. The stale recovery goroutine reclaims jobs running for 5+ minutes, but maxJobDuration allows jobs to run for 10 minutes. A legitimate 7-minute feed sync would be reclaimed as stale while still executing, causing duplicate processing.
**Blast radius:** One constant change in `pool.go`.
**Fix approach:** Set `staleThreshold >= maxJobDuration` (e.g., both 10 minutes, or stale at 12 minutes).

### I17. Dual HTTP framework (huma vs chi) creates inconsistent API surface
**Severity:** MAJOR
**Dimensions:** Code Quality, Architecture, API Design
**Location:** `internal/api/` — CVE routes via huma, all other routes via chi, plus `openapi_spec.go` (1734 lines)
**Evidence:** Two handler paradigms with different validation, error formatting (application/json vs application/problem+json), and documentation strategies. The 1734-line openapi_spec.go manually duplicates type definitions for chi-backed routes. The `password_change_required` response at middleware_auth.go:87-94 uses inline `json.NewEncoder` with a raw map that omits the `status` field, deviating from both patterns.
**Blast radius:** Large — incremental migration of chi handlers to huma would touch most handler files. Not a quick fix.
**Fix approach:** Long-term: migrate chi handlers to huma incrementally. Short-term: fix the `password_change_required` response to use `writeProblem`.

### I18. Inconsistent pagination — 6 list endpoints have no pagination
**Severity:** MINOR (downgraded from MAJOR — most affected collections are naturally small)
**Dimensions:** API Design
**Location:** `channels.go:211`, `orgs.go:188`, `orgs.go:497`, `apikeys.go:152`, `reports.go:201`, `feeds.go:46`
**Evidence:** These list endpoints return all rows without limit or cursor. Feeds (fixed small set) and invitations (naturally few) are fine. Channels, API keys, and reports could theoretically grow but are unlikely to reach problematic sizes at MVP scale.
**Blast radius:** Would require adding pagination to 3-4 endpoints.
**Fix approach:** Add pagination to channels, API keys, and reports. Leave feeds and invitations as-is.

### I19. Store test helpers silently discard errors from CreateOrg/CreateUser
**Severity:** MINOR
**Dimensions:** Test Quality
**Location:** Pattern across multiple test files — e.g., `internal/store/alert_rule_test.go:39`, `internal/notify/dispatcher_test.go:32`
**Evidence:** Many test setup calls use `org, _ := s.CreateOrg(ctx, "...")`, discarding the error. If the test DB is in an unexpected state, these return nil and the test panics later with an unhelpful nil dereference.
**Blast radius:** Many test files. Mechanical fix — replace `_ =` with `require.NoError`.
**Fix approach:** Find all `_, _ :=` or `x, _ :=` patterns in test setup calls and replace with proper error checking using `t.Fatalf` or `require.NoError`.

### I20. `password_change_required` response bypasses `writeProblem` helper
**Severity:** MINOR
**Dimensions:** API Design
**Location:** `internal/api/middleware_auth.go:87-94`
**Evidence:** Uses inline `json.NewEncoder(w).Encode(map[string]string{...})` instead of the shared `writeProblem` helper. The response omits the `status` field that all other error responses include and that RFC 9457 recommends.
**Blast radius:** One code block in middleware_auth.go.
**Fix approach:** Replace inline JSON encoding with `writeProblem(w, http.StatusForbidden, "Your password must be changed before continuing")` or a dedicated `writeProblemTyped` call that includes the `password_change_required` type.

### I21. Log level reload via secrets file does not take effect
**Severity:** MINOR
**Dimensions:** Ops Readiness
**Location:** `internal/config/reloadable.go:126-128`, `cmd/cvert-ops/main.go` (newLogger)
**Evidence:** Hot-reloading the log level via SIGHUP updates `ReloadableConfig.LogLevel` atomically, but no code reads the updated value to reconfigure the `slog` handler. The logger is created once at startup and never updated.
**Blast radius:** `cmd/cvert-ops/main.go` — need to wire the reload callback to update the slog handler's level.
**Fix approach:** Use `slog.LevelVar` for the handler level. On reload, call `levelVar.Set(newLevel)`.

### I22. `NullString("")` conflates empty string with absent value
**Severity:** MINOR
**Dimensions:** Code Quality
**Location:** `internal/dbutil/null.go:10-12`
**Evidence:** `NullString` returns `{Valid: false}` for empty input. The merge pipeline at `merge/pipeline.go:160` calls `dbutil.NullString(resolved.Status)` — if a source explicitly sets status to empty string, it stores as NULL, indistinguishable from "field not provided."
**Blast radius:** `dbutil/null.go` + callers that rely on the empty-string-is-NULL behavior. Need to audit whether any caller intentionally depends on this.
**Fix approach:** Consider renaming to `NullStringOrEmpty` or adding a separate `NullStringPreserveEmpty` variant. Audit callers before changing.

### I23. `isPermanentDeliveryError` uses string matching on error messages for SMTP codes
**Severity:** MINOR
**Dimensions:** Code Quality
**Location:** `internal/notify/worker.go:349-365`
**Evidence:** Checks for SMTP 5xx codes via `strings.Contains` on the error message string. Depends on exact formatting of go-mail library error messages.
**Blast radius:** One function in `worker.go`.
**Fix approach:** Investigate if the go-mail library exposes a typed SMTP error with a status code field. If so, use type assertion instead of string matching.

### I24. Stale comment documents `?after=` instead of `?cursor=` in alert events handler
**Severity:** MINOR
**Dimensions:** API Design
**Location:** `internal/api/alert_events.go:34`
**Evidence:** Function comment says "via ?after= cursor" but the code at line 68 reads `r.URL.Query().Get("cursor")`.
**Blast radius:** One comment.
**Fix approach:** Update the comment to say `?cursor=`.

### I25. No EPSS two-statement pattern integration test
**Severity:** MINOR
**Dimensions:** Test Quality
**Location:** `internal/feed/epss/adapter_test.go`
**Evidence:** The EPSS adapter has a critical two-statement write pattern (update existing CVE + insert to `epss_staging` for non-existent CVE). No test exercises both statements against a real database.
**Blast radius:** New test file or additions to existing EPSS adapter tests.
**Fix approach:** Add an integration test that: (1) inserts a known CVE, runs EPSS adapter, verifies `epss_score` updated; (2) runs EPSS adapter for a CVE that doesn't exist yet, verifies `epss_staging` row created.

### I26. No pending-token-as-access-token rejection test
**Severity:** MINOR
**Dimensions:** Test Quality
**Location:** `internal/auth/jwt_test.go`, `internal/api/middleware_auth_test.go`
**Evidence:** No test verifies that a pending token (MFA-restricted session) is rejected when presented as a regular access token. The middleware tests use only access tokens.
**Blast radius:** New test case in middleware_auth_test.go.
**Fix approach:** Issue a pending token, present it to a route protected by `RequireAuthenticated`, verify it's rejected (401 or 403).

### I27. `TestBuildSafeClient` only checks timeout — doesn't verify redirect or MaxConnsPerHost
**Severity:** MINOR
**Dimensions:** Test Quality
**Location:** `internal/notify/webhook_test.go:230-235`
**Evidence:** The test verifies `BuildSafeClient` returns a non-nil client with a 10-second timeout but doesn't check that redirect following is disabled or `MaxConnsPerHost: 50`, both documented requirements.
**Blast radius:** One test function.
**Fix approach:** Add assertions for redirect policy (attempt redirect, verify it's not followed) and transport settings.

### I28. Frontend uses raw `fetch()` for several endpoints, bypassing typed client
**Severity:** MINOR
**Dimensions:** API Design
**Location:** `web/src/stores/auth.ts:81,102,120`, `web/src/views/admin/AdminSystemView.vue:75`, `web/src/views/LoginView.vue:29`
**Evidence:** forgot-password, reset-password, verify-email, admin doctor, and auth providers all use raw `fetch()` instead of the typed `openapi-fetch` client, losing type safety and the automatic refresh interceptor.
**Blast radius:** Several frontend files.
**Fix approach:** Migrate these calls to the typed client where possible. For unauthenticated endpoints (auth providers, forgot-password), a separate unauth client may be needed.

### I29. `testChannelHandler` always returns HTTP 200 even when the test fails
**Severity:** MINOR
**Dimensions:** API Design
**Location:** `internal/api/channels.go:521`
**Evidence:** Returns `writeJSON(w, http.StatusOK, resp)` where `resp.Success` may be `false`. Most APIs would return 502 or 422 for a failed test delivery.
**Blast radius:** One handler function.
**Fix approach:** Return a non-2xx status code when the test delivery fails, or document this as intentional behavior.

### I30. No `Cache-Control` headers on any API response
**Severity:** MINOR
**Dimensions:** API Design
**Location:** No middleware or handler sets `Cache-Control`
**Evidence:** Authenticated endpoints lack `Cache-Control: no-store` (intermediate caches could cache sensitive data). Public CVE endpoints lack caching directives (every request hits the backend).
**Blast radius:** Middleware addition for authenticated routes. Per-handler for public routes.
**Fix approach:** Add `Cache-Control: no-store` to the auth middleware chain. Consider `Cache-Control: public, max-age=60` for the public CVE list endpoint.

### I31. Feed client has no response body size limit
**Severity:** MINOR
**Dimensions:** Ops Readiness
**Location:** `cmd/cvert-ops/main.go:177`
**Evidence:** Feed HTTP client has `Timeout: 5 * time.Minute` but no response body size limit. A malicious or buggy upstream could return a multi-gigabyte response body, causing OOM within the 1GB container memory limit.
**Blast radius:** `cmd/cvert-ops/main.go` — wrap the client transport to limit response body size.
**Fix approach:** Add an `io.LimitReader` wrapper in the feed HTTP client's transport or in each adapter's response handling.

---

## Design Decisions Requiring User Input

### D1. CVE endpoints are fully unauthenticated
**Flagged by:** API Design (Agent 5), also flagged in March 10 review (M18)
**The concern:** The entire CVE corpus is publicly accessible with only IP rate limiting (10 req/min). Any unauthenticated user can enumerate all CVEs.
**Why this needs a decision:** The code comment says "auth middleware added in Phase 2." If this is tracked Phase 2 work, it's expected. But if production deployment happens before Phase 2, the full corpus is exposed.
**Options:**
  - (A) Leave as-is — this is tracked Phase 2 work
  - (B) Add basic auth before any production deployment
  - (C) Increase IP rate limits to make scraping slower
**Recommendation:** Option A if production deployment requires Phase 2 completion. Flag it if production could happen earlier.

### D2. No circuit breaker or health-aware retry on outbound feed HTTP
**Flagged by:** Architecture (Agent 2)
**The concern:** Feed adapters use a simple 5-minute timeout HTTP client. When an upstream is degraded, worker pool slots fill with hanging requests, blocking healthy feeds.
**Why this needs a decision:** This is a real concern at scale but adds complexity. At MVP scale with few concurrent feeds, the impact is limited.
**Options:**
  - (A) Accept for MVP — monitor via feed health metrics
  - (B) Add per-feed circuit breaker now
  - (C) Add a simpler per-feed error counter with auto-disable after N consecutive failures
**Recommendation:** Option C — simpler than a full circuit breaker but provides fast-fail for degraded feeds.

### D3. No graceful degradation when Postgres is slow or unavailable at runtime
**Flagged by:** Architecture (Agent 2)
**The concern:** No load shedding when DB is under pressure. All components continue issuing queries that timeout, goroutines accumulate.
**Why this needs a decision:** Full load shedding is complex. The pgxpool connection limit (25) provides some protection. This is primarily a concern for production under load.
**Options:**
  - (A) Accept for MVP — the 25-connection pool limit provides basic backpressure
  - (B) Add connection acquisition timeout to fail fast
  - (C) Add health-aware request rejection in middleware
**Recommendation:** Option B as a quick win — `pgxpool.Config.AcquireTimeout` limits how long requests wait for a connection.

### D4. API key query string rejection middleware
**Flagged by:** API Design (Agent 5)
**The concern:** No middleware rejects requests that include API keys in query parameters, which would be logged by proxies and browsers.
**Why this needs a decision:** Agent 5 claimed this was a PLAN.md §16 requirement, but I searched PLAN.md thoroughly and this specific requirement does not exist. It is a valid security best practice, however.
**Options:**
  - (A) Add the middleware — good security hygiene regardless of PLAN.md
  - (B) Skip — API keys are sent via `Authorization: Bearer` header; query string usage is a client mistake, not a server problem
**Recommendation:** Option A — it's cheap to implement and prevents common client mistakes.

### D5. import-bulk CLI subcommand still a stub
**Flagged by:** Architecture (Agent 2)
**The concern:** The command logs "not yet implemented" and returns nil.
**Why this needs a decision:** The March 10 review flagged this but then INVALIDATED the finding because NVD doesn't offer bulk download files. PLAN.md §3.3 describes bulk import from local files for offline/airgapped scenarios, not as the primary first-run mechanism. Normal API polling is the intended initial sync path.
**Options:**
  - (A) Accept as-is — this is a feature for airgapped deployments, not blocking MVP
  - (B) Implement for offline scenarios as planned
  - (C) Remove the stub command to avoid confusion
**Recommendation:** Option A for now; implement when airgapped deployment is needed.

---

## False Positives

### FP1. "Missing API key query string rejection middleware — PLAN.md §16 requirement"
**Flagged by:** API Design (Agent 5)
**Why invalid:** Agent claimed PLAN.md section 16 "explicitly requires returning 400 Bad Request if a request includes an API key in any query parameter." I searched PLAN.md thoroughly — this specific requirement does not exist. The security concern is valid (reclassified as D4 above), but the PLAN.md citation is fabricated. The severity was based on a non-existent spec violation.

### FP2. "import-bulk is critical for initial data population"
**Flagged by:** Architecture (Agent 2)
**Why invalid:** The March 10 review investigated this and invalidated it. NVD does not offer bulk download files. The normal API polling path is the intended initial sync mechanism. The import-bulk stub is for offline/airgapped scenarios. The agent's characterization of PLAN.md §3.3 was misleading — §3.3 describes bulk sources like MITRE's JSON files, not a critical blocking dependency.

---

## Known / Already Tracked

### K1. Dual HTTP framework (huma vs chi) inconsistency
**Flagged by:** Code Quality, Architecture, API Design (all 3 agents)
**Where tracked:** March 10 health review M6, M8. Incremental huma migration is a known long-term effort.

### K2. serve/worker command duplication
**Flagged by:** Architecture, Ops Readiness
**Where tracked:** March 10 health review M17.

### K3. No container healthcheck for production
**Flagged by:** Ops Readiness
**Where tracked:** March 10 health review C3.

### K4. CVE endpoints unauthenticated
**Flagged by:** API Design
**Where tracked:** March 10 health review M18. Code comment says "Phase 2."

### K5. Per-org semaphore map grows without bound
**Flagged by:** Ops Readiness
**Where tracked:** March 10 health review M14. Eviction was added since then but has a timing issue (only evicts when channel buffer is empty at eviction time).

### K6. Inconsistent pagination / list response shapes
**Flagged by:** API Design
**Where tracked:** March 10 health review M7, M9.
