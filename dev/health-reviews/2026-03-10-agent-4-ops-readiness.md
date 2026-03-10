# Agent 4: Operational Readiness
**Date:** 2026-03-10
**Scope:** Full review

---

### [CRITICAL] Alert evaluation paths (Realtime, Batch, EPSS) are implemented but never wired into the runtime

**Evidence:** `EvaluateRealtime`, `EvaluateBatch`, `EvaluateEPSS`, and `SweepZombieActivations` in `internal/alert/evaluator.go` are fully implemented and tested but never called outside test files. No feed ingestion triggers `EvaluateRealtime`. No cron or scheduler calls `EvaluateBatch` or `EvaluateEPSS`.

**Problem:** The core alerting feature is implemented but never invoked in production. The three-path evaluation model described in PLAN.md §10.3 is entirely dead code.

**Risk:** Ship-blocking. Users configure rules, see them go "active," and receive nothing.

---

### [CRITICAL] RLS defense-in-depth is bypassed — application connects as database superuser

**Evidence:** `docker/init.sql` creates the `cvert_ops_app` role with `NOBYPASSRLS`, but `docker/compose.yml:111-112` and `:136-137` show both the app and migrate services connect as `${POSTGRES_USER:-cvert_ops}` (the superuser). The `cvert_ops_app` role's password is commented out in init.sql line 19.

**Problem:** The entire RLS architecture (PLAN.md §6, `NOBYPASSRLS`, `FORCE ROW LEVEL SECURITY`) is bypassed because the application connects as the database superuser, which inherently bypasses all RLS policies. The restricted role exists in the init script but is never used. All the careful `SET LOCAL app.org_id` calls in the store layer are no-ops against a superuser connection.

**Risk:** A SQL injection or application bug that escapes tenant isolation has no database-level safety net. RLS is specifically defense-in-depth against application-level bugs, and it's not active. This is a security product managing vulnerability data for multiple tenants.

**Suggested approach:** Update compose.yml to have the app service connect as `cvert_ops_app`. Keep the migrate service on the superuser. Uncomment and set the app role password. Verify RLS policies actually block cross-tenant access with an integration test.

---

### [CRITICAL] Container has no health check; orchestrator cannot determine readiness

**Evidence:** `docker/Dockerfile` has no `HEALTHCHECK` directive. The app container's `/healthz` endpoint exists but no container health check uses it. Caddy at compose.yml line 195 uses `depends_on: [app]` with no health condition. The app's DB connection retry loop can take up to 55 seconds.

**Problem:** Orchestrators (Kubernetes, ECS, Compose) cannot determine if the app is serving traffic. Caddy starts forwarding traffic before the app is ready. During the DB retry window, the app returns errors to any request routed to it.

**Risk:** During deployments, traffic is routed to containers that haven't finished starting, causing 502/503 errors. Rolling deployments cannot safely drain old instances because the orchestrator has no readiness signal.

**Suggested approach:** Add `HEALTHCHECK --interval=5s --timeout=3s CMD ["/app", "healthcheck"]` to Dockerfile. Add a `/readyz` endpoint that checks DB + worker pool + scheduler status. Use `service_healthy` condition in Caddy's `depends_on`.

---

### [MAJOR] `stdlib.OpenDBFromPool` returns `*sql.DB` instances that are never closed

**Evidence:** `cmd/cvert-ops/main.go:146` and `main.go:265` both call `stdlib.OpenDBFromPool(db)` and pass the result to `alert.New()`. Neither the returned `*sql.DB` nor `store.New()`'s internal `*sql.DB` is ever closed. Only the underlying `pgxpool.Pool` is closed via `defer db.Close()`.

**Problem:** `stdlib.OpenDBFromPool` returns a `*sql.DB` that wraps the pool with its own goroutines and state. Per pgx docs, it should be closed when done.

**Risk:** Potential connection/goroutine leak. Less severe for a long-running server but still a correctness issue.

**Suggested approach:** Track the `*sql.DB` and `defer stdDB.Close()` before pool close.

---

### [MAJOR] No metrics for job queue, worker throughput, notification delivery, feed errors, or alert evaluation

**Evidence:** `internal/metrics/` contains only `ai.go`. The only non-AI Prometheus metrics are in `internal/ingest/scheduler.go` (feed job enqueue/skip counters). Zero metrics in: `internal/worker/`, `internal/notify/`, `internal/alert/`, `internal/merge/`, `internal/retention/`.

**Problem:** An operator cannot answer basic questions from metrics: "How many jobs are pending?", "What's the average feed ingestion time?", "How many notifications failed?", "Is the alert evaluator running?", "How long does merge take?"

**Risk:** First sign of problems will be user complaints, not a metrics alert. Cannot set up SLOs or operational alerting on this system's health.

**Suggested approach:** Add Prometheus counters/histograms for: job claim/complete/fail rates, job queue depth gauge, feed ingest duration, merge duration, notification delivery latency/success/failure, alert evaluation duration/match counts.

---

### [MAJOR] `REGISTRATION_MODE` defaults to "open" — contradicts documentation saying "invite-only"

**Evidence:** `internal/config/config.go:35` — `envDefault:"open"`. CLAUDE.md and PLAN.md state the default is `invite-only`. `validateConfig` does not check or warn about this.

**Problem:** A production deployment that relies on the documented default (or omits the env var) allows unrestricted public registration. This is a security product.

**Risk:** Unauthorized users can self-register and create organizations, consuming resources and potentially accessing shared CVE data.

**Suggested approach:** Change the default to `invite-only` to match documentation, or add a startup warning when `REGISTRATION_MODE=open` and `APP_ENV=production`.

---

### [MAJOR] `COOKIE_SECURE` defaults to `false` — no validation that it's `true` in production

**Evidence:** `internal/config/config.go:43` — `envDefault:"false"`. While `validateConfig` checks `EXTERNAL_URL` for HTTPS, there's no corresponding check that `COOKIE_SECURE=true` when `APP_ENV != "development"`.

**Problem:** Auth cookies sent over HTTP are vulnerable to interception. An operator could deploy with HTTPS but forget this env var.

**Risk:** Session hijacking via network sniffing if any HTTP path exists (before redirect, mixed content, misconfigured proxy).

**Suggested approach:** In `validateConfig`, enforce `COOKIE_SECURE=true` when `APP_ENV=production` and `EXTERNAL_URL` starts with `https://`.

---

### [MAJOR] Worker pool passes cancellable context to job handlers — in-flight jobs fail during shutdown

**Evidence:** `internal/worker/pool.go:142` — `p.processOne(ctx, queue)` passes the process-lifetime context. When SIGTERM fires, `ctx.Done()` triggers and in-flight jobs receive a cancelled context. Compare with notification worker at `worker.go:139` which correctly uses `context.WithoutCancel(ctx)`.

**Problem:** During shutdown, `inflight.Wait()` waits for in-flight jobs, but those jobs' DB queries and HTTP calls immediately fail with `context.Canceled`.

**Risk:** In-flight jobs fail during graceful shutdown instead of completing. They'll be recovered after 5 minutes by stale-job recovery, creating a window of re-execution and delay.

**Suggested approach:** Use `context.WithoutCancel(ctx)` for the context passed to job handlers, matching the notification worker pattern.

---

### [MAJOR] Notification worker per-org semaphore map grows without bound

**Evidence:** `internal/notify/worker.go:340-347` — `semaphore()` creates a new buffered channel per `orgID` in `w.sems` map with no eviction.

**Problem:** Over the process lifetime, every org that ever receives a notification gets a permanent entry. Each entry is small (~200 bytes), but in a multi-tenant SaaS deployment with thousands of orgs, this grows indefinitely.

**Risk:** Unbounded memory growth proportional to distinct org count. Unlikely to cause OOM but indicates the map was designed for hot orgs, not all orgs ever seen.

**Suggested approach:** Add an LRU eviction or periodic cleanup for org semaphores not used within the last N minutes.

---

### [MINOR] DB statement timeout (14s) may be too low for long-running operations

**Evidence:** `internal/config/config.go:25` — `envDefault:"14000"`. Applied globally. No per-operation override.

**Problem:** Activation scans, complex DSL queries, and large merge operations may exceed 14 seconds.

**Risk:** Legitimate operations silently killed, appearing as intermittent failures.

---

### [MINOR] `expectedSchemaVersion` constant must be manually synchronized with migrations

**Evidence:** `cmd/cvert-ops/main.go:529` — `const expectedSchemaVersion = 30`.

**Problem:** Manual constant. Developers can forget to update it when adding migrations.

**Risk:** Advisory warning fires incorrectly, operators learn to ignore it.
