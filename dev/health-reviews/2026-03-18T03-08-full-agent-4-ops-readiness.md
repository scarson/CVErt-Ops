# Agent 4: Operational Readiness
**Date:** 2026-03-18 03:08
**Scope:** Full review

### [MAJOR] No job queue depth metric

**Evidence:** `internal/metrics/worker.go` defines `cvertops_worker_jobs_claimed_total` and `cvertops_worker_jobs_completed_total` but no gauge for pending/queued jobs. No `queue_depth`, `pending_jobs`, or `backlog` metric exists anywhere in the codebase.
**Problem:** An operator cannot answer "how far behind is the system?" without querying the database directly. If feed ingestion falls behind or alert evaluation jobs pile up, there is no Prometheus alert target to detect it. This is the single most important metric for a job-queue system and it is missing.
**Risk:** Silent backlog growth goes undetected until users notice stale data or missing alerts. By then recovery may require hours of catch-up processing.

### [MAJOR] Delivery worker shutdown not awaited in serve mode

**Evidence:** `cmd/cvert-ops/main.go:261` starts the delivery worker as a fire-and-forget goroutine. The `Start` method blocks until ctx is cancelled, then calls `w.wg.Wait()` internally. However, in `runServe`, after `ctx.Done()` fires, the function proceeds directly to `srv.Shutdown(shutdownCtx)` and returns. Nothing waits for the delivery worker goroutine to complete. The `defer db.Close()` at line 121 may close the database pool while in-flight deliveries (which use `context.WithoutCancel`) are still executing.
**Problem:** In-flight webhook or email deliveries that were already claimed and detached from the parent context via `context.WithoutCancel` (line 164 of `notify/worker.go`) may be interrupted when the DB pool closes, leaving deliveries in a "processing" state with no clear recovery path until the stuck-delivery reset timer fires on next startup.
**Risk:** Notifications silently lost during graceful shutdown. Users miss critical vulnerability alerts.

### [MAJOR] Delivery worker shutdown not awaited in worker mode

**Evidence:** `cmd/cvert-ops/main.go:446` launches the delivery worker goroutine. At line 487, `workerPool.Start(ctx)` blocks. When that returns (after context cancellation + drain), the function proceeds to metrics server shutdown and returns. The delivery worker goroutine is never joined.
**Problem:** Same as the serve mode issue -- claimed deliveries using `context.WithoutCancel` are racing against `defer db.Close()` at line 379.
**Risk:** Same as above: notification loss on shutdown.

### [MAJOR] No container healthcheck for the app service in production

**Evidence:** `docker/compose.prod.yml:83-84`: "No healthcheck -- distroless has no shell/curl." The `docker/Dockerfile` does not install any health check binary and exposes only port 8080 (no 9090). The production compose file has no healthcheck for the app service.
**Problem:** Docker/Compose cannot detect a hung or unhealthy app container. The `restart: unless-stopped` policy only triggers on process exit, not on a stuck process. The `/healthz` and `/readyz` endpoints exist but nothing in the container orchestration layer calls them.
**Risk:** A process that is alive but non-functional (e.g., deadlocked, DB pool exhausted, stuck migration lock) will not be restarted by Docker. In a non-Kubernetes deployment, this means an indefinite outage.

### [MAJOR] Metrics port not exposed in Dockerfile or production compose

**Evidence:** `docker/Dockerfile:39` only has `EXPOSE 8080`. The metrics server listens on `:9090` (default `METRICS_PORT`). The `docker/compose.prod.yml` comment says "App metrics port (9090) on internal network only (not exposed to host)" but the compose file does not actually map port 9090 at all -- neither in the base `compose.yml` app service nor in `compose.prod.yml`.
**Problem:** Prometheus cannot scrape the metrics endpoint from outside the container network. Operators deploying with the provided compose files get zero observability from Prometheus.
**Risk:** All the carefully implemented metrics (feed health, worker jobs, DB pool, notification delivery, alert evaluation) are invisible to monitoring. Operators are flying blind.

### [MAJOR] Security event writer goroutines have no timeout or bound

**Evidence:** `internal/secure/writer.go:71-107` -- each `Write` call spawns a new goroutine with `context.WithoutCancel`. The goroutine inserts into the database and optionally sends to syslog. There is no limit on concurrent goroutines and no timeout on the detached context.
**Problem:** Under a brute-force attack or security event flood that exceeds the rate limiter (10/min per key), goroutines still spawn for allowed events. If the database is slow (e.g., during a connection pool exhaustion event), these goroutines pile up with no bound, each holding a `wg.Add(1)` that prevents `Stop()` from completing. Furthermore, `Stop()` is called via `defer eventWriter.Stop()` at line 203 of `main.go`, which blocks indefinitely if any goroutine is stuck on a slow DB query with no context timeout.
**Risk:** Process hangs during shutdown. Under heavy security event load with a degraded database, unbounded goroutine growth leads to OOM.

### [MINOR] REGISTRATION_MODE not validated at startup

**Evidence:** `config.Config.RegistrationMode` defaults to `"invite-only"` and the only check is `srv.cfg.RegistrationMode != "open"` at `internal/api/auth.go:120`. The `validateConfig` function in `main.go` does not check that `RegistrationMode` is one of the valid values.
**Problem:** A typo like `REGISTRATION_MODE=inviteonly` silently disables open registration (because `!= "open"` is true) but may confuse operators who expect it to be open. More importantly, there is no validation that the value is one of the known modes.
**Risk:** Misconfiguration goes undetected; operator intent is silently violated.

### [MINOR] DB_QUERY_EXEC_MODE not validated

**Evidence:** `cmd/cvert-ops/main.go:699` checks `if cfg.DBQueryExecMode == "simple_protocol"` but does not validate the value. A typo like `DB_QUERY_EXEC_MODE=simple` silently falls through and uses the pgx default (extended protocol), which breaks PgBouncer transaction pooling.
**Problem:** Invalid configuration value silently uses a potentially incompatible protocol mode.
**Risk:** Prepared statement errors or connection issues in PgBouncer deployments that are hard to diagnose because the config appears correct.

### [MINOR] Feed client has no response body size limit

**Evidence:** `cmd/cvert-ops/main.go:177` creates a feed HTTP client with `Timeout: 5 * time.Minute` but no `MaxResponseBodySize` or `io.LimitReader` wrapper. Feed adapters use this client to fetch data from external APIs (NVD, MITRE, GHSA, OSV, etc.).
**Problem:** A compromised or misbehaving upstream feed source could return a multi-gigabyte response body. The 5-minute timeout limits total time but not data volume. With the 1GB container memory limit in production, a large response body causes OOM kill.
**Risk:** A single malicious or buggy feed response can crash the worker or server process.

### [MINOR] No notification delivery queue depth metric

**Evidence:** The notification delivery subsystem tracks `cvertops_notification_deliveries_total` (success/failure/exhausted) and `cvertops_notification_delivery_duration_seconds`, but there is no gauge for pending deliveries awaiting processing. The `ClaimPendingDeliveries` call returns rows but the count is not reported as a metric.
**Problem:** Operators cannot monitor notification delivery backlog growth. If the SMTP server is slow or a webhook endpoint is timing out, the pending delivery queue grows silently.
**Risk:** Alert notifications delayed by hours without operator visibility.

### [MINOR] Retention cleanup has no Prometheus metrics

**Evidence:** `internal/retention/runner.go` logs deletion counts via slog but does not emit any Prometheus counters or histograms. There are no metrics for rows deleted per table, runtime duration, or max-runtime-reached events.
**Problem:** Operators cannot monitor whether retention cleanup is running, how much data it deletes, or whether it is hitting the max runtime ceiling. The only signal is log lines, which are harder to alert on.
**Risk:** Table growth goes undetected if retention cleanup silently fails or is unable to keep up.

### [MINOR] Per-org semaphore map in notification worker grows without bound under certain timing

**Evidence:** `internal/notify/worker.go:380-402` -- the semaphore eviction at line 392 only evicts entries where `len(w.sems[orgID]) == 0`, checking channel buffer length. However, if a delivery is in-flight (buffer has items), the semaphore is never evicted. The eviction ticker runs every 10 minutes. In a system with thousands of orgs, each org that has had a delivery creates a permanent map entry that is only evicted if it has zero in-flight items at the exact moment the eviction ticker fires.
**Problem:** The semaphore map is a minor memory leak in multi-tenant deployments with many orgs. Each entry is a channel (small) plus map overhead, so this is unlikely to cause OOM, but it grows monotonically in the worst case.
**Risk:** Marginal memory growth over months in high-tenant deployments.

### [MINOR] Standalone worker mode has no readiness endpoint

**Evidence:** `cmd/cvert-ops/main.go:470-484` -- the standalone `workerCmd` exposes a metrics server on the metrics port with only `/metrics`. There is no `/healthz` or `/readyz` endpoint. The delivery worker `Healthy()` check is registered via `apiSrv.AddHealthCheck` only in serve mode.
**Problem:** In a deployment where the worker runs as a separate process (the documented `cvert-ops worker` command), there is no way for an orchestrator to check worker health. The metrics server only serves Prometheus scrape data.
**Risk:** A hung worker process is not detected by the orchestrator.

### [MINOR] Auto-migrate advisory lock blocks indefinitely

**Evidence:** `cmd/cvert-ops/main.go:615` -- `pg_advisory_lock` blocks until the lock is acquired. There is no timeout on this call. If a previous migration process died without releasing the lock (e.g., OOM kill while the connection is still alive on the Postgres side), the new process blocks forever at startup.
**Problem:** Session-level advisory locks are released when the session ends, so this is only a problem if the old session is still alive (e.g., long TCP keepalive, PgBouncer holding the connection). The context passed to ExecContext could timeout, but `cmd.Context()` has no deadline.
**Risk:** Startup hangs during rolling updates if the previous instance database connection has not been cleaned up yet. Recovery requires manual intervention (`pg_terminate_backend`).

### [MINOR] Log level reload via secrets file does not take effect

**Evidence:** `internal/config/reloadable.go:126-128` stores the reloaded `LOG_LEVEL` in `ReloadableConfig.LogLevel`, and `internal/config/reload.go:29` atomically updates the holder. However, there is no code that reads `configHolder.Load().LogLevel` and calls `slog.SetDefault()` with an updated handler. The logger is created once at startup (`newLogger` in `main.go` line 795) and never updated.
**Problem:** Hot-reloading the log level via SIGHUP or the admin API updates the config struct but has no effect on actual log output.
**Risk:** Operators changing log level for debugging must restart the process, which is the opposite of the expected behavior of a hot-reload feature.

### [MINOR] init.sql uses hardcoded development password

**Evidence:** `docker/init.sql:19` -- `ALTER ROLE cvert_ops_app WITH LOGIN PASSWORD` uses a hardcoded dev password. This file is mounted into the Postgres container and runs on first initialization.
**Problem:** The comment says "In production, use a secrets manager instead" but the compose files use this same init.sql in both dev and production overlays. The production compose file sets `APP_DB_PASSWORD` with a default of `cvert_ops_app_dev`, matching this hardcoded password. There is no mechanism to override the init.sql password.
**Risk:** Production deployments using the provided compose files have a predictable database application password. Combined with the `cvert-data-net` being `internal: true`, the blast radius is limited, but it remains a credential management gap.

### [MINOR] SMTP defaults point to development Mailpit in production

**Evidence:** `internal/config/config.go:83-84` -- `SMTPHost` defaults to `"localhost"` and `SMTPPort` defaults to `1025`. These are Mailpit defaults. There is no startup validation that SMTP settings are production-appropriate when `APP_ENV=production`.
**Problem:** If an operator deploys to production and forgets to set `SMTP_HOST` and `SMTP_PORT`, email notifications (password reset, MFA OTP, alert emails) silently fail or are delivered to nothing. The error would appear in logs but there is no startup check.
**Risk:** Email-dependent functionality (password reset, MFA email OTP, email notification channels) silently broken in production.

### [MINOR] Duplicate code between serve and worker command initialization

**Evidence:** `cmd/cvert-ops/main.go:105-351` (runServe) and `main.go:363-495` (runWorker) share approximately 80% identical initialization code: config loading, pool creation, metrics registration, feed config loading, alert evaluator creation, notification worker creation, feed scheduler creation.
**Problem:** This is not a production readiness issue per se, but the duplication means that a fix applied to one path (e.g., adding a new worker registration, fixing a shutdown sequence) can easily be missed in the other. The delivery worker shutdown issue noted above exists identically in both paths precisely because of this duplication.
**Risk:** Divergent behavior between serve and worker modes as the codebase evolves. Bugs fixed in one path are missed in the other.

### [MINOR] Stale job threshold (5 min) is shorter than max job duration (10 min)

**Evidence:** `internal/worker/pool.go:34-39` -- `staleThreshold = 5 * time.Minute` and `maxJobDuration = 10 * time.Minute`. The stale recovery goroutine runs every 1 minute and reclaims jobs that have been running for 5+ minutes.
**Problem:** A legitimately running job (e.g., a large NVD feed sync that takes 7 minutes) will be reclaimed as stale while the original goroutine is still executing it. Both the original and the reclaimed job will attempt to merge the same data, leading to wasted work and potential race conditions in cursor updates.
**Risk:** Large feed syncs are prematurely reclaimed, causing duplicate processing. The merge pipeline idempotency via `ON CONFLICT` prevents data corruption, but the wasted work and confusing log output (two workers processing the same feed simultaneously) make debugging difficult.
