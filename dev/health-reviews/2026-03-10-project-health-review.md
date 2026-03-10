# Project Health Review — CVErt Ops
**Date:** 2026-03-10
**Scope:** Full review across all dimensions

---

## Critical Findings

### 1. Alert evaluation paths (Realtime, Batch, EPSS) are implemented but never wired into the runtime
**Dimensions:** Architecture & Design, Operational Readiness
**Evidence:** `EvaluateRealtime`, `EvaluateBatch`, `EvaluateEPSS`, and `SweepZombieActivations` in `internal/alert/evaluator.go` are fully implemented and tested but never called outside test files. The only non-test caller is `EvaluateActivation` (via the `alert_activation` worker handler in `cmd/cvert-ops/main.go:312`). No feed ingestion triggers `EvaluateRealtime`. No cron or scheduler calls `EvaluateBatch` or `EvaluateEPSS`.
**Problem:** The core alerting feature — the reason this product exists — is implemented but never invoked. Users can create alert rules that activate successfully, but no alerts will ever fire from ongoing CVE changes. The three-path evaluation model (realtime on material_hash change, batch on date_modified_canonical cursor, EPSS-specific on date_epss_updated cursor) described in PLAN.md §10.3 is entirely dead code in production.
**Risk:** A deployed instance accepts alert rule configurations but silently never delivers any alerts. Users would configure rules, see them go "active," and receive nothing. Ship-blocking.
**Suggested approach:** Wire `EvaluateRealtime` as a post-merge hook in the ingest pipeline. Register `EvaluateBatch` and `EvaluateEPSS` as scheduled worker jobs (like `feed_ingest`). Wire `SweepZombieActivations` as a periodic cleanup task.

### 2. RLS defense-in-depth is bypassed — application connects as database superuser
**Dimensions:** Operational Readiness
**Evidence:** `docker/init.sql` creates the `cvert_ops_app` role with `NOBYPASSRLS`, but `docker/compose.yml:111-112` and `:136-137` show both the app and migrate services connect as `${POSTGRES_USER:-cvert_ops}` (the superuser). The `cvert_ops_app` role's password is commented out in init.sql line 19.
**Problem:** The entire RLS architecture (PLAN.md §6, `NOBYPASSRLS`, `FORCE ROW LEVEL SECURITY`) is bypassed because the application connects as the database superuser, which inherently bypasses all RLS policies. The restricted role exists in the init script but is never used. All the careful `SET LOCAL app.org_id` calls in the store layer are no-ops against a superuser connection.
**Risk:** A SQL injection or application bug that escapes tenant isolation has no database-level safety net. RLS is specifically defense-in-depth against application-level bugs, and it's not active. This is a security product managing vulnerability data for multiple tenants.
**Suggested approach:** Update compose.yml to have the app service connect as `cvert_ops_app`. Keep the migrate service on the superuser. Uncomment and set the app role password. Verify RLS policies actually block cross-tenant access with an integration test.

### 3. Container has no health check; orchestrator cannot determine readiness
**Dimensions:** Operational Readiness
**Evidence:** `docker/Dockerfile` has no `HEALTHCHECK` directive. The app container's `/healthz` endpoint exists but no container health check uses it. Caddy at compose.yml line 195 uses `depends_on: [app]` with no health condition. The app's DB connection retry loop can take up to 55 seconds.
**Problem:** Orchestrators (Kubernetes, ECS, Compose) cannot determine if the app is serving traffic. Caddy starts forwarding traffic before the app is ready. During the DB retry window, the app returns errors to any request routed to it.
**Risk:** During deployments, traffic is routed to containers that haven't finished starting, causing 502/503 errors. Rolling deployments cannot safely drain old instances because the orchestrator has no readiness signal.
**Suggested approach:** Add `HEALTHCHECK --interval=5s --timeout=3s CMD ["/app", "healthcheck"]` to Dockerfile (or `curl -f http://localhost:8080/healthz`). Add a `/readyz` endpoint that checks DB + worker pool + scheduler status. Use `service_healthy` condition in Caddy's `depends_on`.

---

## Major Findings

### 4. `api.Server.Close()` never called during shutdown — background goroutines leak
**Dimensions:** Architecture & Design, Operational Readiness
**Evidence:** `internal/api/server.go:129-142` defines `Server.Close()` which stops the IP rate limiter, org rate limiter, tier cache, and lockout manager cleanup goroutines. `cmd/cvert-ops/main.go` creates `apiSrv` at line 138 but never calls `apiSrv.Close()` — only `srv.Shutdown()` on the `http.Server`.
**Problem:** Four background goroutines (each with their own ticker) are started in `NewServer` and never stopped on shutdown. The `Close()` method exists and is properly called in tests, but the production entrypoint omits it.
**Risk:** Incomplete shutdown. Currently masked because the process exits, but leaking goroutines if the server lifecycle changes (hot-reload, graceful restart, library usage).
**Suggested approach:** Add `defer apiSrv.Close()` in `runServe` after `apiSrv` creation.

### 5. `stdlib.OpenDBFromPool` returns `*sql.DB` instances that are never closed
**Dimensions:** Operational Readiness
**Evidence:** `cmd/cvert-ops/main.go:146` and `main.go:265` both call `stdlib.OpenDBFromPool(db)` and pass the result to `alert.New()`. Neither the returned `*sql.DB` nor `store.New()`'s internal `*sql.DB` is ever closed. Only the underlying `pgxpool.Pool` is closed via `defer db.Close()`.
**Problem:** `stdlib.OpenDBFromPool` returns a `*sql.DB` that wraps the pool with its own goroutines and state. Per pgx docs, it should be closed when done.
**Risk:** Potential connection/goroutine leak. Less severe for a long-running server but still a correctness issue.
**Suggested approach:** Track the `*sql.DB` and `defer stdDB.Close()` before pool close.

### 6. Inconsistent error response format: chi handlers return plaintext, huma handlers return RFC 9457
**Dimensions:** API Design & Developer Experience
**Evidence:** All chi-registered handlers (orgs, watchlists, channels, alert_rules, groups, deliveries, reports, apikeys, audit_log, saved_searches) use `http.Error(w, "message", statusCode)` returning `text/plain`. Huma-registered handlers (auth, cves) return `huma.Error4xxXxx()` generating RFC 9457 Problem Details JSON.
**Problem:** PLAN.md §16 mandates RFC 9457 Problem Details for all error responses. The majority of the API returns bare text errors instead. An API consumer's generic error handler that parses JSON problem details will get parse failures on most endpoints.
**Risk:** Every client must handle two completely different error formats depending on which endpoint they hit. This is the single most visible inconsistency to API consumers.
**Suggested approach:** Migrate chi-registered handlers to huma, or create a shared error response helper that writes RFC 9457 JSON from chi handlers.

### 7. Inconsistent list response shapes — some paginated objects, some bare arrays
**Dimensions:** API Design & Developer Experience
**Evidence:** `GET /cves` and `GET /watchlists` return `{"items": [...], "next_cursor": "..."}`. But `GET /members`, `GET /api-keys`, `GET /invitations`, `GET /groups`, `GET /group-members`, `GET /saved-searches` return bare JSON arrays `[...]`.
**Problem:** Clients must know per-endpoint whether to read `response.items` or treat the response as the array. Adding pagination later to bare-array endpoints is a breaking change.
**Risk:** Frontend already handles both shapes. Future pagination on members/groups/api-keys requires a breaking response shape change.
**Suggested approach:** Wrap all list responses in `{"items": [...]}` consistently. Add pagination support to currently-unpaginated endpoints that could grow (members, api-keys).

### 8. Dual API client on frontend — typed openapi-fetch for huma routes, untyped orgFetch for chi routes
**Dimensions:** API Design & Developer Experience
**Evidence:** `web/src/lib/api/client.ts` creates a typed `openapi-fetch` client, but `web/src/lib/api/orgFetch.ts` is a separate untyped fetch wrapper. The typed client is only used for auth and CVE endpoints. Every org-scoped endpoint uses `orgFetch` with manual URL construction and `as` type casts.
**Problem:** Chi-registered handlers are not in the OpenAPI spec (only huma routes get generated), forcing the frontend to bypass the typed client for most of the API. No compile-time type safety for most API calls.
**Risk:** Type drift between frontend and backend is invisible until runtime. If the backend adds or renames a field, no build step catches the mismatch.
**Suggested approach:** This is a downstream symptom of the chi/huma split. Migrating chi handlers to huma would auto-generate OpenAPI coverage and enable the typed client for all endpoints.

### 9. Inconsistent pagination cursor mechanisms across endpoints
**Dimensions:** API Design & Developer Experience
**Evidence:** Six different pagination patterns: (1) CVE list: `?cursor=`, base64 JSON, `base64.RawURLEncoding`; (2) Watchlists/alert-rules: `?after=`, base64 `time|uuid`, `base64.URLEncoding`; (3) Deliveries: `?after_created_at=` + `?after_id=` as separate params; (4) Watchlist items: `?after=`, raw UUID; (5) Saved searches: not paginated; (6) Alert rules: hardcoded `limit=20`, no client-controllable page size.
**Problem:** A client developer cannot predict how pagination works for any given endpoint. Parameter names, encoding, and cursor opacity all vary.
**Risk:** Each new endpoint integration requires figuring out a novel pagination contract. The delivery cursor's `next_cursor` response value doesn't match its expected input format — it's unusable as returned.
**Suggested approach:** Standardize on a single opaque cursor pattern (e.g., base64 JSON `{"d":"...","id":"..."}`) for all paginated endpoints with a shared `?cursor=` param.

### 10. No metrics for job queue, worker throughput, notification delivery, feed errors, or alert evaluation
**Dimensions:** Operational Readiness
**Evidence:** `internal/metrics/` contains only `ai.go`. The only non-AI Prometheus metrics are in `internal/ingest/scheduler.go` (feed job enqueue/skip counters). Zero metrics in: `internal/worker/`, `internal/notify/`, `internal/alert/`, `internal/merge/`, `internal/retention/`.
**Problem:** An operator cannot answer basic questions from metrics: "How many jobs are pending?", "What's the average feed ingestion time?", "How many notifications failed?", "Is the alert evaluator running?", "How long does merge take?"
**Risk:** First sign of problems will be user complaints, not a metrics alert. Cannot set up SLOs or operational alerting on this system's health.
**Suggested approach:** Add Prometheus counters/histograms for: job claim/complete/fail rates, job queue depth gauge, feed ingest duration, merge duration, notification delivery latency/success/failure, alert evaluation duration/match counts.

### 11. `REGISTRATION_MODE` defaults to "open" — contradicts documentation saying "invite-only"
**Dimensions:** Operational Readiness
**Evidence:** `internal/config/config.go:35` — `envDefault:"open"`. CLAUDE.md and PLAN.md state the default is `invite-only`. `validateConfig` does not check or warn about this.
**Problem:** A production deployment that relies on the documented default (or omits the env var) allows unrestricted public registration. This is a security product.
**Risk:** Unauthorized users can self-register and create organizations, consuming resources and potentially accessing shared CVE data.
**Suggested approach:** Change the default to `invite-only` to match documentation, or add a startup warning when `REGISTRATION_MODE=open` and `APP_ENV=production`.

### 12. `COOKIE_SECURE` defaults to `false` — no validation that it's `true` in production
**Dimensions:** Operational Readiness
**Evidence:** `internal/config/config.go:43` — `envDefault:"false"`. While `validateConfig` checks `EXTERNAL_URL` for HTTPS, there's no corresponding check that `COOKIE_SECURE=true` when `APP_ENV != "development"`.
**Problem:** Auth cookies sent over HTTP are vulnerable to interception. An operator could deploy with HTTPS but forget this env var.
**Risk:** Session hijacking via network sniffing if any HTTP path exists (before redirect, mixed content, misconfigured proxy).
**Suggested approach:** In `validateConfig`, enforce `COOKIE_SECURE=true` when `APP_ENV=production` and `EXTERNAL_URL` starts with `https://`.

### 13. Worker pool passes cancellable context to job handlers — in-flight jobs fail during shutdown
**Dimensions:** Operational Readiness
**Evidence:** `internal/worker/pool.go:142` — `p.processOne(ctx, queue)` passes the process-lifetime context. When SIGTERM fires, `ctx.Done()` triggers and in-flight jobs receive a cancelled context. Compare with notification worker at `worker.go:139` which correctly uses `context.WithoutCancel(ctx)`.
**Problem:** During shutdown, `inflight.Wait()` waits for in-flight jobs, but those jobs' DB queries and HTTP calls immediately fail with `context.Canceled`.
**Risk:** In-flight jobs fail during graceful shutdown instead of completing. They'll be recovered after 5 minutes by stale-job recovery, creating a window of re-execution and delay.
**Suggested approach:** Use `context.WithoutCancel(ctx)` for the context passed to job handlers, matching the notification worker pattern.

### 14. Notification worker per-org semaphore map grows without bound
**Dimensions:** Operational Readiness
**Evidence:** `internal/notify/worker.go:340-347` — `semaphore()` creates a new buffered channel per `orgID` in `w.sems` map with no eviction.
**Problem:** Over the process lifetime, every org that ever receives a notification gets a permanent entry. Each entry is small (~200 bytes), but in a multi-tenant SaaS deployment with thousands of orgs, this grows indefinitely.
**Risk:** Unbounded memory growth proportional to distinct org count. Unlikely to cause OOM but indicates the map was designed for hot orgs, not all orgs ever seen.
**Suggested approach:** Add an LRU eviction or periodic cleanup for org semaphores not used within the last N minutes.

### 15. `api` package is a monolith with 18+ direct import dependencies and temporal coupling
**Dimensions:** Architecture & Design
**Evidence:** `internal/api` imports `internal/ai`, `internal/alert`, `internal/alert/dsl`, `internal/audit`, `internal/auth`, `internal/config`, `internal/crypto`, `internal/ingest`, `internal/metrics`, `internal/notify`, `internal/store`, `internal/store/generated`, `internal/tier`, plus OAuth, JWT, and HTTP framework packages. The `Server` struct has 13 fields with setter methods (`SetAlertDeps`, `SetAIDeps`, `SetAuditDeps`) called at different times.
**Problem:** Every domain concept terminates in this package. The multi-phase `Set*Deps` initialization is a temporal coupling anti-pattern — wrong ordering produces nil-pointer panics.
**Risk:** As features grow, this package becomes harder to test, compile, and reason about. Any new domain feature requires modifying the central `server.go` wiring.
**Suggested approach:** Consider grouping handler registrations by domain (e.g., `api/alerts/`, `api/cves/`) or at minimum replacing `Set*Deps` with a single options struct validated at construction time.

### 16. Dual worker systems (generic Pool + notify Worker) operating independently
**Dimensions:** Architecture & Design
**Evidence:** `internal/worker.Pool` claims from `job_queue` with `SKIP LOCKED`. `internal/notify.Worker` has its own claim/retry/stuck-reset cycle against `notification_deliveries`, plus manages digest scheduling and retention job enqueuing. Both started as independent goroutines.
**Problem:** The notification worker has evolved into a mini-scheduler with five tickers that duplicates concepts from the generic worker pool. It has no metrics, no health endpoint, and no visibility into its internal state.
**Risk:** Operational blindness. If the notification worker stops claiming or gets stuck, there is no alerting mechanism. The generic worker pool has metrics via the scheduler, but the notification worker is a black box.
**Suggested approach:** Either migrate notification delivery to the generic worker pool (as a `notification_delivery` job type) or add equivalent health metrics to the notification worker.

### 17. `runServe` and `runWorker` share ~80% identical setup with no factoring
**Dimensions:** Architecture & Design
**Evidence:** `cmd/cvert-ops/main.go` lines 91-229 (`runServe`) and 241-307 (`runWorker`) both create config, logger, pool, store, feed client, worker pool, EPSS handler, alert evaluator, notification worker, etc. with nearly identical code.
**Problem:** Any change to worker setup must be made in two places. `runServe` wires LLM client and audit writer; `runWorker` does not. If a worker handler needs LLM access, standalone worker mode silently gets nil.
**Risk:** Feature parity bugs between `serve` and `worker` modes. A standalone worker deployment could silently lack capabilities.
**Suggested approach:** Extract shared setup into a `buildApp()` function that returns a struct with all wired dependencies.

### 18. CVE endpoints are unauthenticated
**Dimensions:** API Design & Developer Experience
**Evidence:** `registerCVERoutes` (cves.go line 25) is mounted outside `RequireAuthenticated()` middleware. Comment says "All endpoints are public read-only — auth middleware is added in Phase 2."
**Problem:** The CVE corpus is the core data asset. Public access means any unauthenticated user can enumerate the entire CVE database, including data from authenticated/paid feeds.
**Risk:** If deployed without Phase 2, the entire CVE dataset is public, potentially violating terms of upstream data sources.
**Suggested approach:** This is tracked as Phase 2 work but should be prioritized before any production deployment.

### 19. `import-bulk` subcommand is a stub
**Dimensions:** Architecture & Design
**Evidence:** `cmd/cvert-ops/main.go:413-422` logs "not yet implemented" and returns nil.
**Problem:** PLAN.md §3.3 identifies bulk import as essential for initial data population. NVD rate limits at 5 req/30s — API-only backfill for ~250k CVEs takes days to weeks.
**Risk:** Initial setup of a new instance requires extended API polling. Network errors during this multi-day backfill require retry. Self-hosted users see an empty corpus for an extended period.
**Suggested approach:** Implement at least NVD bulk import (annual JSON archives) before production readiness.

### 20. Duplicated post-filter logic between evaluator and store
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/alert/evaluator.go:527-576` (`applyPostFilters` + `postFilterTarget`) and `internal/store/dsl_executor.go:237-283` (`applyDSLPostFilters` + `dslPostFilterTarget`). ~90 lines of near-identical regex filter application with AND/OR logic, differing only in input type.
**Problem:** Two copies of the same filter logic that must stay synchronized. When filter behavior needs to change, one copy gets updated and the other doesn't.
**Risk:** Inconsistent filter behavior between alert evaluation and saved-search execution.
**Suggested approach:** Extract post-filter logic into a shared generic function parameterized on the input type, or define a common interface both types implement.

### 21. `queryCandidates` and `queryCandidatesAll` are ~90-line near-duplicates
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/alert/evaluator.go:428-473` and `evaluator.go:478-523`. Identical SELECT, FROM, join loop, LIMIT, scan loop — only difference is an optional `WHERE cve_id = ANY(?)` clause.
**Problem:** A bug fix or column change in one method is easily missed in the other.
**Risk:** Divergent candidate query behavior between realtime and batch evaluation paths.
**Suggested approach:** Merge into one method with an optional `candidateIDs []string` parameter (nil = no filter).

### 22. Ingest handler tests verify mock behavior, not real merge logic
**Dimensions:** Test Quality
**Evidence:** `internal/ingest/handler_test.go` lines 22-68 use `mockMerge` to record calls. All assertions verify mock call counts and arguments, never that data is correctly persisted.
**Problem:** The integration between handler, real adapters, and real merge pipeline is untested end-to-end. A bug in how the handler transforms patches or handles partial failures during merge would not be caught.
**Risk:** Data-flow bugs from adapter response through merge to database could ship undetected.
**Suggested approach:** Add at least one integration test that uses a real merge function and real DB, verifying data persistence end-to-end.

### 23. No feed adapter tests with real upstream response shapes (golden files)
**Dimensions:** Test Quality
**Evidence:** All adapter tests use `httptest.NewServer` with handcrafted JSON. No golden-file tests with captured real responses.
**Problem:** Hand-maintained fixtures may drift from actual upstream API response formats. If NVD changes their JSON schema, the adapter silently produces wrong patches and tests still pass.
**Risk:** Feed ingestion silently producing empty or malformed patches after upstream API changes, with no test breakage.
**Suggested approach:** Capture real responses from each feed API and add golden-file parse tests that verify the adapter produces expected `CanonicalPatch` output.

### 24. Email notification tests skip when SMTP unavailable — security-critical header injection test is effectively unrun
**Dimensions:** Test Quality
**Evidence:** `internal/notify/email_test.go:25-27` skips if Mailpit not running. The header injection test (line 70-81) is security-critical but will skip in any CI without Mailpit.
**Problem:** The project already uses testcontainers for Postgres — the same pattern should apply to SMTP. The `TestEmailSend_SubjectHeaderInjection` test never verifies the injection was actually stripped, even when Mailpit is available.
**Risk:** A regression in email header injection protection goes undetected in CI.
**Suggested approach:** Use an Inbucket testcontainer (already added per recent commit `f253dc2`). Update the injection test to query the SMTP server and verify the `Bcc` header was stripped.

### 25. Store is a concrete struct passed through the entire system — merge pipeline accesses raw DB
**Dimensions:** Architecture & Design
**Evidence:** `internal/store.Store` is concrete. `internal/merge.Ingest` takes `*store.Store`. The merge pipeline calls `s.DB()` and `s.Pool()` directly, bypassing abstractions.
**Problem:** Impossible to test the merge pipeline without a real database. Some sub-interfaces exist (`worker.JobStore`, `store.AlertRuleStore`) but the core data path takes the full concrete store.
**Risk:** Test suite is slow and fragile due to mandatory Postgres dependency for all integration tests. Adding a second storage backend requires rewriting the merge pipeline.
**Suggested approach:** Define a `MergeStore` interface consumed by the merge pipeline with the specific methods it needs. This enables testing with a fake store and decouples merge from the full store surface area.

---

## Minor Findings

### 26. `readTx` method on Evaluator defined but never called
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/alert/evaluator.go:608-615`. Grep for `.readTx(` returns zero results across non-test files.
**Problem:** Dead code that misleads readers about the evaluator's transaction model. `DryRun` uses `bypassTx` instead.
**Risk:** A contributor might use `readTx` thinking it's the intended read path.

### 27. sqlc generates `Cfe` as the Go type name for the `cves` table
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/store/generated/models.go:182` — `type Cfe struct`.
**Problem:** Confusing inflection of "cves" → "Cfe". Every new contributor will spend time figuring out this is the CVE row type.
**Risk:** Readability. Fixable with a `rename` directive in sqlc config.

### 28. Duplicated `toNullString` helpers across three packages
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/merge/pipeline.go:298`, `internal/store/ai.go:240`, `internal/store/watchlist.go:312`. Three separate implementations of the same `sql.NullString` conversion.
**Problem:** Small helpers re-invented per-package rather than extracted.
**Risk:** Pattern of avoiding shared utilities will compound as codebase grows.

### 29. SMTP permanent error detection relies on string matching
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/notify/worker.go:317-324` — `isPermanentDeliveryError` scans `err.Error()` for string prefixes like `"550 "`.
**Problem:** Fragile — depends on exact error formatting from the go-mail library.
**Risk:** Permanent errors misclassified as transient, wasting delivery retries and hitting SMTP rate limits.

### 30. Evaluator mixes `*sql.DB` and `store.AlertRuleStore` — duplicates RLS bypass pattern
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/alert/evaluator.go:44-49` holds both `db *sql.DB` and `rules store.AlertRuleStore`, duplicating `bypassTx` independently of the store's transaction helpers.
**Problem:** Two independent implementations of the bypass transaction pattern. If RLS bypass mechanism changes, the evaluator's copy is easily missed.
**Risk:** Inconsistent RLS bypass behavior.

### 31. No `Location` header on 201 Created responses
**Dimensions:** API Design & Developer Experience
**Evidence:** All creation handlers (watchlists, channels, alert_rules, api-keys, groups, reports, saved_searches) return 201 without `Location`.
**Problem:** RFC 9110 §15.3.2 recommends `Location` header. Machine clients expect it.
**Risk:** Minor friction for API integrators — they must parse the body to find the resource URL.

### 32. PATCH on groups uses non-pointer fields — cannot clear optional values
**Dimensions:** API Design & Developer Experience
**Evidence:** `groups.go:29-33` — `updateGroupBody` uses `string` not `*string`.
**Problem:** PLAN.md §16 mandates pointer types for PATCH fields. Sending `{"description": ""}` is indistinguishable from omitting it.
**Risk:** Clients cannot make partial updates or clear fields.

### 33. Inconsistent validation error status codes (400 vs 422 for same error)
**Dimensions:** API Design & Developer Experience
**Evidence:** "name is required" returns 422 in channels.go and reports.go, but 400 in groups.go, watchlists.go, alert_rules.go, and saved_searches.go.
**Problem:** Same validation failure uses different status codes per endpoint.
**Risk:** Clients cannot use status codes to distinguish parse errors from validation errors.

### 34. Tier limit violations return 403 — indistinguishable from RBAC rejections
**Dimensions:** API Design & Developer Experience
**Evidence:** `createAlertRuleHandler` line 199, plus watchlists, channels, orgs — all return 403 for tier limits.
**Problem:** 403 semantically means "no permission." Tier limits are a different concept (quota exhausted). Clients can't distinguish "wrong role" from "need higher tier."
**Risk:** Confusing error handling for clients and frontend.

### 35. `InCISAKEV` boolean filter silently treats non-"true" values as false
**Dimensions:** API Design & Developer Experience
**Evidence:** `cves.go:261-263` — `strings.EqualFold(i.InCISAKEV, "true")`. Sending `?in_cisa_kev=yes` or `?in_cisa_kev=1` silently filters to false.
**Problem:** No validation error on invalid boolean values. Users get silently wrong results.
**Risk:** Users get fewer results than expected from a typo or convention mismatch, with no error to diagnose.

### 36. Advisory lock test does not actually verify lock acquisition
**Dimensions:** Test Quality
**Evidence:** `internal/merge/pipeline_integration_test.go:546-583` — test comment admits the limitation. Only checks that `CVEAdvisoryKey` is deterministic, not that the lock was acquired.
**Problem:** Misleading test name gives false confidence. If lock acquisition code were removed, this test still passes.
**Risk:** Regression in advisory locking would not be caught by this named test.

### 37. Several store tests silently discard setup errors
**Dimensions:** Test Quality
**Evidence:** Pattern across `internal/store/store_test.go` — `org1, _ := s.CreateOrg(ctx, ...)`, `user1, _ := s.CreateUser(ctx, ...)`.
**Problem:** If setup fails (migration issue, constraint violation), tests proceed with zero-value UUIDs and produce confusing assertion failures.
**Risk:** Root cause of infrastructure failures is obscured.

### 38. No readiness probe distinct from liveness probe
**Dimensions:** Architecture & Design
**Evidence:** `/healthz` is the only health endpoint. It checks DB ping only. No `/readyz` that checks worker pool, scheduler, and notification worker status.
**Problem:** During startup, HTTP server accepts requests before background systems are initialized.
**Risk:** Load balancer routes traffic to instances whose background systems aren't running — alert rule creation returns 202 for scans that won't execute.

### 39. `BootstrapFirstUserOrg` uses manual transaction management instead of `withBypassTx`
**Dimensions:** Code Quality & Go Idiom
**Evidence:** `internal/store/org.go:66-123` — manual tx open, bypass_rls set, advisory lock, custom serialization.
**Problem:** More error-prone than the defer-based `withBypassTx` pattern. Mixed transaction management styles.
**Risk:** Future code paths added between `BeginTx` and defer could leak uncommitted transactions.

### 40. `GetCVEDetail` comment claims parallel queries but executes sequentially
**Dimensions:** Architecture & Design
**Evidence:** `internal/store/cve.go:30` comment says "fetches child tables in parallel queries." Lines 39-55: calls are sequential.
**Problem:** Misleading comment could prevent someone from implementing the actual optimization.
**Risk:** 4 sequential round trips instead of 2. Fine at current scale, bites with remote databases.

### 41. `TestExecuteDSLQuery_EmptyConditions` has no assertion — cannot fail
**Dimensions:** Test Quality
**Evidence:** `internal/store/dsl_executor_test.go:132-148` — logs both outcomes, never asserts.
**Problem:** Both success and failure are logged with `t.Log`. Test always passes.
**Risk:** Behavior change on empty conditions is never caught.

### 42. `DownloadToTemp_SizeLimit` test mutates package-level state
**Dimensions:** Test Quality
**Evidence:** `internal/feed/util_test.go:326-346` — modifies package-level `MaxDownloadSize`, not safe with parallel tests.
**Problem:** Race window if other tests call `DownloadToTemp` concurrently.
**Risk:** Intermittent CI failures; blocks safe parallelization of the feed package tests.

### 43. Delivery list cursor is unusable — response format doesn't match request format
**Dimensions:** API Design & Developer Experience
**Evidence:** `deliveries.go:88` — `next_cursor` is `<RFC3339Nano>/<uuid>` combined, but the endpoint expects `after_created_at` + `after_id` as separate params.
**Problem:** Client cannot forward `next_cursor` from response back as a query parameter.
**Risk:** Clients must ignore `next_cursor` and manually extract values from the last item.

### 44. DB statement timeout (14s) may be too low for long-running operations
**Dimensions:** Operational Readiness
**Evidence:** `internal/config/config.go:25` — `envDefault:"14000"`. Applied globally. No per-operation override.
**Problem:** Activation scans, complex DSL queries, and large merge operations may exceed 14 seconds.
**Risk:** Legitimate operations silently killed, appearing as intermittent failures.

### 45. `expectedSchemaVersion` constant must be manually synchronized with migrations
**Dimensions:** Operational Readiness
**Evidence:** `cmd/cvert-ops/main.go:529` — `const expectedSchemaVersion = 30`.
**Problem:** Manual constant. Developers can forget to update it when adding migrations.
**Risk:** Advisory warning fires incorrectly, operators learn to ignore it.

---

## Cross-Cutting Themes

### Theme 1: The chi/huma handler split is the root cause of most API inconsistencies
Findings 6, 7, 8, 9, 31, 32, 33, 34 all stem from the same architectural decision: some handlers use huma (with automatic OpenAPI generation, RFC 9457 errors, and struct validation) while others use raw chi (with manual JSON encoding, plaintext errors, and ad-hoc validation). Migrating the chi handlers to huma would resolve or significantly improve all of these findings simultaneously.

### Theme 2: Alert pipeline is complete but disconnected
Finding 1 (alert paths not wired) is the highest-severity gap. Combined with Finding 10 (no alert metrics), Finding 36 (advisory lock test limitations), and the evaluator code duplication (Findings 20, 21), the alert system is thorough in implementation but has no production integration. This is simultaneously the project's core value proposition and its largest gap.

### Theme 3: Production readiness has systematic gaps
Findings 2 (RLS bypass), 3 (no health check), 4 (Server.Close leak), 5 (sql.DB leak), 10 (no metrics), 11 (registration mode), 12 (cookie secure), 13 (worker context), 44 (statement timeout), and 45 (schema version) form a pattern: the application logic is well-built but the operational envelope around it is incomplete. A production deployment would work functionally but be difficult to operate, monitor, and secure.

### Theme 4: Code duplication in the alert evaluator
Findings 20, 21, 26, and 30 all point to the alert evaluator having grown organically without periodic refactoring. Post-filters are duplicated with the store, candidate queries are duplicated internally, dead methods linger, and transaction management is implemented independently of the store's helpers.
