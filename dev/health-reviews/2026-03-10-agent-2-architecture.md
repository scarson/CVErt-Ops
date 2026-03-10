# Agent 2: Architecture & Design
**Date:** 2026-03-10
**Scope:** Full review

---

### [CRITICAL] Alert evaluation paths (Realtime, Batch, EPSS) are implemented but never wired into the runtime

**Evidence:** `EvaluateRealtime`, `EvaluateBatch`, `EvaluateEPSS`, and `SweepZombieActivations` in `internal/alert/evaluator.go` are fully implemented and tested but never called outside test files. The only non-test caller is `EvaluateActivation` (via the `alert_activation` worker handler in `cmd/cvert-ops/main.go:312`). No feed ingestion triggers `EvaluateRealtime`. No cron or scheduler calls `EvaluateBatch` or `EvaluateEPSS`.

**Problem:** The core alerting feature — the reason this product exists — is implemented but never invoked. Users can create alert rules that activate successfully, but no alerts will ever fire from ongoing CVE changes. The three-path evaluation model (realtime on material_hash change, batch on date_modified_canonical cursor, EPSS-specific on date_epss_updated cursor) described in PLAN.md §10.3 is entirely dead code in production.

**Risk:** A deployed instance accepts alert rule configurations but silently never delivers any alerts. Users would configure rules, see them go "active," and receive nothing. Ship-blocking.

**Suggested approach:** Wire `EvaluateRealtime` as a post-merge hook in the ingest pipeline. Register `EvaluateBatch` and `EvaluateEPSS` as scheduled worker jobs (like `feed_ingest`). Wire `SweepZombieActivations` as a periodic cleanup task.

---

### [MAJOR] `api.Server.Close()` never called during shutdown — background goroutines leak

**Evidence:** `internal/api/server.go:129-142` defines `Server.Close()` which stops the IP rate limiter, org rate limiter, tier cache, and lockout manager cleanup goroutines. `cmd/cvert-ops/main.go` creates `apiSrv` at line 138 but never calls `apiSrv.Close()` — only `srv.Shutdown()` on the `http.Server`.

**Problem:** Four background goroutines (each with their own ticker) are started in `NewServer` and never stopped on shutdown. The `Close()` method exists and is properly called in tests, but the production entrypoint omits it.

**Risk:** Incomplete shutdown. Currently masked because the process exits, but leaking goroutines if the server lifecycle changes (hot-reload, graceful restart, library usage).

**Suggested approach:** Add `defer apiSrv.Close()` in `runServe` after `apiSrv` creation.

---

### [MAJOR] `api` package is a monolith with 18+ direct import dependencies and temporal coupling

**Evidence:** `internal/api` imports `internal/ai`, `internal/alert`, `internal/alert/dsl`, `internal/audit`, `internal/auth`, `internal/config`, `internal/crypto`, `internal/ingest`, `internal/metrics`, `internal/notify`, `internal/store`, `internal/store/generated`, `internal/tier`, plus OAuth, JWT, and HTTP framework packages. The `Server` struct has 13 fields with setter methods (`SetAlertDeps`, `SetAIDeps`, `SetAuditDeps`) called at different times.

**Problem:** Every domain concept terminates in this package. The multi-phase `Set*Deps` initialization is a temporal coupling anti-pattern — wrong ordering produces nil-pointer panics.

**Risk:** As features grow, this package becomes harder to test, compile, and reason about. Any new domain feature requires modifying the central `server.go` wiring.

**Suggested approach:** Consider grouping handler registrations by domain (e.g., `api/alerts/`, `api/cves/`) or at minimum replacing `Set*Deps` with a single options struct validated at construction time.

---

### [MAJOR] Dual worker systems (generic Pool + notify Worker) operating independently

**Evidence:** `internal/worker.Pool` claims from `job_queue` with `SKIP LOCKED`. `internal/notify.Worker` has its own claim/retry/stuck-reset cycle against `notification_deliveries`, plus manages digest scheduling and retention job enqueuing. Both started as independent goroutines.

**Problem:** The notification worker has evolved into a mini-scheduler with five tickers that duplicates concepts from the generic worker pool. It has no metrics, no health endpoint, and no visibility into its internal state.

**Risk:** Operational blindness. If the notification worker stops claiming or gets stuck, there is no alerting mechanism. The generic worker pool has metrics via the scheduler, but the notification worker is a black box.

**Suggested approach:** Either migrate notification delivery to the generic worker pool (as a `notification_delivery` job type) or add equivalent health metrics to the notification worker.

---

### [MAJOR] `runServe` and `runWorker` share ~80% identical setup with no factoring

**Evidence:** `cmd/cvert-ops/main.go` lines 91-229 (`runServe`) and 241-307 (`runWorker`) both create config, logger, pool, store, feed client, worker pool, EPSS handler, alert evaluator, notification worker, etc. with nearly identical code.

**Problem:** Any change to worker setup must be made in two places. `runServe` wires LLM client and audit writer; `runWorker` does not. If a worker handler needs LLM access, standalone worker mode silently gets nil.

**Risk:** Feature parity bugs between `serve` and `worker` modes. A standalone worker deployment could silently lack capabilities.

**Suggested approach:** Extract shared setup into a `buildApp()` function that returns a struct with all wired dependencies.

---

### [MAJOR] `import-bulk` subcommand is a stub

**Evidence:** `cmd/cvert-ops/main.go:413-422` logs "not yet implemented" and returns nil.

**Problem:** PLAN.md §3.3 identifies bulk import as essential for initial data population. NVD rate limits at 5 req/30s — API-only backfill for ~250k CVEs takes days to weeks.

**Risk:** Initial setup of a new instance requires extended API polling. Network errors during this multi-day backfill require retry. Self-hosted users see an empty corpus for an extended period.

**Suggested approach:** Implement at least NVD bulk import (annual JSON archives) before production readiness.

---

### [MAJOR] Store is a concrete struct passed through the entire system — merge pipeline accesses raw DB

**Evidence:** `internal/store.Store` is concrete. `internal/merge.Ingest` takes `*store.Store`. The merge pipeline calls `s.DB()` and `s.Pool()` directly, bypassing abstractions.

**Problem:** Impossible to test the merge pipeline without a real database. Some sub-interfaces exist (`worker.JobStore`, `store.AlertRuleStore`) but the core data path takes the full concrete store.

**Risk:** Test suite is slow and fragile due to mandatory Postgres dependency for all integration tests. Adding a second storage backend requires rewriting the merge pipeline.

**Suggested approach:** Define a `MergeStore` interface consumed by the merge pipeline with the specific methods it needs. This enables testing with a fake store and decouples merge from the full store surface area.

---

### [MINOR] No readiness probe distinct from liveness probe

**Evidence:** `/healthz` is the only health endpoint. It checks DB ping only. No `/readyz` that checks worker pool, scheduler, and notification worker status.

**Problem:** During startup, HTTP server accepts requests before background systems are initialized.

**Risk:** Load balancer routes traffic to instances whose background systems aren't running — alert rule creation returns 202 for scans that won't execute.

---

### [MINOR] `GetCVEDetail` comment claims parallel queries but executes sequentially

**Evidence:** `internal/store/cve.go:30` comment says "fetches child tables in parallel queries." Lines 39-55: calls are sequential.

**Problem:** Misleading comment could prevent someone from implementing the actual optimization.

**Risk:** 4 sequential round trips instead of 2. Fine at current scale, bites with remote databases.

---

### [MINOR] CVE endpoints are unauthenticated

**Evidence:** `registerCVERoutes` (cves.go line 25) is mounted outside `RequireAuthenticated()` middleware. Comment says "All endpoints are public read-only — auth middleware is added in Phase 2."

**Problem:** The CVE corpus is the core data asset. Public access means any unauthenticated user can enumerate the entire CVE database, including data from authenticated/paid feeds.

**Risk:** If deployed without Phase 2, the entire CVE dataset is public, potentially violating terms of upstream data sources. Tracked as Phase 2 work but should be prioritized before any production deployment.
