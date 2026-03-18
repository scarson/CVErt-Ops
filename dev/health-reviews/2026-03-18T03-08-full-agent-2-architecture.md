# Agent 2: Architecture & Design
**Date:** 2026-03-18 03:08
**Scope:** Full review

### [MAJOR] API package is a God package with 112 handlers and imports from 17 internal packages

**Evidence:** internal/api/ contains 48k+ lines across 68+ Go files. It imports internal/ai, internal/alert, internal/alert/dsl, internal/audit, internal/auth, internal/config, internal/crypto, internal/doctor, internal/feed, internal/ingest, internal/log, internal/merge, internal/metrics, internal/notify, internal/secure, internal/store, internal/store/generated, internal/tier, and web. The Server struct holds 24 fields.

**Problem:** The API layer is a coupling hub. Every new feature adds another dependency. The Server struct acts as a service locator. The ingest handler directly calls merge.Ingest, coupling API to the merge pipeline.

**Risk:** Adding any new feature requires modifying the central Server struct and potentially recompiling the entire API package.

---

### [MAJOR] Dual HTTP handler patterns create inconsistent API surface

**Evidence:** CVE routes use huma.Register with typed structs. All other routes (112 handlers) use raw chi http.HandlerFunc with manual JSON decode. A separate 1734-line openapi_spec.go manually duplicates type definitions for OpenAPI spec generation.

**Problem:** Two handler paradigms with different validation, error formatting, and documentation strategies. The spec-only file can silently drift from actual handler implementations.

**Risk:** Input validation gaps in chi handlers. OpenAPI spec drift from actual behavior.

---

### [MAJOR] Alert evaluator bypasses the store abstraction layer with raw SQL

**Evidence:** internal/alert/evaluator.go holds its own *sql.DB reference and executes raw SQL queries directly for candidate queries, cursor management, zombie sweep, and CVE batch retrieval. It duplicates the RLS bypass pattern in its own bypassTx method rather than using store.WorkerTx.

**Problem:** The evaluator is a second data access layer parallel to internal/store. The bypassTx method lacks the panic recovery that the store version includes. Direct SQL bypasses any future query auditing or schema evolution.

**Risk:** Schema changes require updates in two places. Missing panic recovery could leave a transaction open.

---

### [MAJOR] Massive code duplication in serve and worker command wiring

**Evidence:** cmd/cvert-ops/main.go contains runServe (lines 105-351) and runWorker (lines 363-495) with nearly identical blocks for: pool creation, feed config loading, alert cache/evaluator setup, worker pool registration, notification wiring, feed scheduler setup, and metrics server.

**Problem:** Any change to worker wiring must be made in two places. The two functions have already diverged: runServe sets up AuditWriter but runWorker does not.

**Risk:** Future changes will be applied to one function and missed in the other. This has already happened with the audit writer.

---

### [MINOR] internal/search/ directory exists but is empty

**Evidence:** ls internal/search/ returns no files. PLAN.md section 4.2 defines cve_search_index with FTS. Search functionality is implemented inline in CVE handlers and store methods.

**Problem:** FTS query building, ranking, and faceted search logic is scattered rather than consolidated.

**Risk:** Low immediate risk but growing complexity will force increasingly complex store methods.

---

### [MAJOR] No circuit breaker or health-aware retry on outbound feed HTTP calls

**Evidence:** Feed adapters receive an *http.Client with a 5-minute timeout. No circuit breaker, no health tracking per upstream, no adaptive backoff based on upstream health.

**Problem:** When an upstream feed is degraded, the system consumes a full 5-minute timeout on each request with no fast-fail mechanism.

**Risk:** During NVD outages, worker pool concurrency slots fill with hanging HTTP calls, blocking healthy feeds.

---

### [MINOR] Notification delivery worker runs as a separate goroutine with its own event loop

**Evidence:** notify.Worker has its own Start method with a select loop over 6 tickers, completely separate from worker.Pool. It reimplements claim/retry/backoff logic, stuck-job detection, and health checks.

**Problem:** Two independent job processing systems exist in the same binary. Operational visibility is split.

**Risk:** Behavior inconsistencies between the two systems. Graceful shutdown coordination is implicit.

---

### [MINOR] The merge.Store interface exposes only DB() *sql.DB, leaking the database abstraction

**Evidence:** internal/merge/store.go defines type Store interface { DB() *sql.DB }. The merge pipeline manages its own transactions, advisory locks, and commit/rollback directly.

**Problem:** The merge pipeline bypasses all store transaction helpers. Exposing *sql.DB through an interface defeats the store abstraction.

**Risk:** Store-layer changes to connection pooling, instrumentation, or lifecycle hooks will not benefit the merge pipeline.

---

### [CRITICAL] Batch and EPSS evaluators load all candidate CVE IDs into memory without pagination

**Evidence:** evaluator.go getCVEsModifiedSince and getCVEsEPSSUpdatedSince execute SELECT cve_id FROM cves WHERE date_modified_canonical > $1 without a LIMIT clause, scanning into an unbounded []string slice. The batch path could return hundreds of thousands of CVE IDs when the cursor falls behind.

**Problem:** After a restart where the batch cursor is stale or zero, getCVEsModifiedSince returns every non-rejected CVE. With 250k+ CVEs, these IDs are passed into a 250k-element ANY() clause in SQL which Postgres cannot efficiently plan. The activation scan correctly paginates in 1000-row batches, but the batch and EPSS paths do not.

**Risk:** First batch evaluation after a fresh install or extended outage OOM-kills the worker or causes Postgres to spend minutes planning the query. Production reliability issue that manifests when the system needs to catch up after downtime.

---

### [MINOR] Retention runner takes a concrete *store.Store, not an interface

**Evidence:** internal/retention/runner.go declares store *store.Store. Compare with internal/worker/pool.go which defines a JobStore interface.

**Problem:** Cannot be unit-tested without a full database.

**Risk:** Low. Tested via integration tests.

---

### [MINOR] Feed adapter factory uses a switch statement rather than a registry pattern

**Evidence:** internal/ingest/feeds.go NewAdapter is a switch on feed name strings. Adding a new adapter requires modifying this function, KnownFeeds, and defaultSchedule.

**Problem:** Registration scattered across multiple locations that must stay in sync manually.

**Risk:** Adding a new feed adapter is error-prone.

---

### [MAJOR] No graceful degradation when Postgres is slow or unavailable at runtime

**Evidence:** The health check (/readyz) verifies the DB pool is connected. But once running, there is no mechanism to stop accepting work when the database is under pressure. Worker pool continues claiming jobs. HTTP server continues accepting requests. All issue DB queries that may time out (14s default).

**Problem:** No load shedding. When Postgres is slow, all components hammer it with timing-out queries. The pgxpool has a 25-connection limit but no queue depth limit -- requests pile up waiting for connections.

**Risk:** Temporary Postgres degradation causes blocked goroutines to accumulate. Memory grows until OOM-kill. No graceful recovery from transient DB issues.

---

### [MINOR] Context keys for request-scoped state create implicit middleware contracts

**Evidence:** Multiple handlers reference r.Context().Value(ctxOrgID), r.Context().Value(ctxUserID), r.Context().Value(ctxTierResolver).

**Problem:** Context keys create an implicit contract between middleware and handlers. A handler mounted outside the org middleware gets a nil assertion at runtime.

**Risk:** Low with good test coverage (which exists).

---

### [MAJOR] import-bulk CLI subcommand is a stub returning immediately

**Evidence:** cmd/cvert-ops/main.go line 678 logs import-bulk not yet implemented. PLAN.md section 3.3 describes import-bulk as critical for initial data population.

**Problem:** The planned backfill mechanism does not exist. PLAN.md explicitly warns against relying solely on API polling for large feeds. Without bulk import, a new instance takes hours to days to populate.

**Risk:** New deployments have an empty CVE corpus for an extended period. Users see zero alerts because the corpus is still populating.

---

### [MINOR] The report package is empty -- digest reports are implemented in the notify package

**Evidence:** internal/report/ directory exists but contains no files. Digest report execution lives in internal/notify/digest.go.

**Problem:** Report generation and delivery are conflated in the notification package. Adding PDF export or API-served reports would require extraction.

**Risk:** Low for current scope. The empty directory suggests planned but unexecuted separation.

---

### [MINOR] Slack notification channel type is missing from the implementation

**Evidence:** PLAN.md section 11.1 lists Slack incoming webhook as an MVP channel. notify.Worker.deliver handles only webhook and email. No Slack-specific formatting exists.

**Problem:** Slack is listed as MVP but not implemented. Generic webhook payloads may not render well in Slack (which expects text or blocks fields).

**Risk:** Users find raw JSON posted to Slack channels instead of formatted messages.
