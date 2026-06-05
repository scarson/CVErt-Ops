# S3 Feed Ingestion — Concurrency & Parallelization Audit

**Date:** 2026-06-05
**Slice:** S3 "Feed ingestion & adapters" (FULL, HOT)
**Lane:** Concurrency & parallelization (EXPLOIT + DEFEND)
**Scope read:** `internal/feed/**`, `internal/ingest/**`, `internal/store/feed.go`, `internal/merge/{pipeline,advisory}.go`, `internal/worker/pool.go`, `cmd/cvert-ops/main.go` (worker wiring + pool config)

Confidence is `Strong-static` or `Heuristic` only — nothing here is measured.

---

### [CRITICAL] EPSS apply runs ~250,000 advisory-locked transactions strictly serially inside one job

**Location:** `internal/feed/epss/adapter.go:202-232` (the `for { cr.Read() ... a.applyRowFn(...) }` loop) → `applyRow` at `:250-287`; driven by `internal/ingest/epss.go:51` `applyFn(ctx, mergeSt.DB(), cursor)` under worker `maxJobDuration = 10m` (`internal/worker/pool.go:41`).

**Problem:** Every daily EPSS run reads ~250k CSV rows and, for each one, opens a fresh `database/sql` transaction, executes `SELECT pg_advisory_xact_lock($1)`, two write statements (`UpdateCVEEPSS`, `UpsertEPSSStaging`), and `Commit()` — all on a single goroutine, one row at a time. That is ~250k × (4 DB round-trips + commit fsync) executed end-to-end with zero overlap. At even a conservative 1ms/round-trip on a local DB this is ~1000s of pure round-trip latency before any lock/fsync cost — comfortably past the 10-minute `maxJobDuration` cap, after which the job context is cancelled mid-stream and the stale-recovery goroutine reclaims it (`pool.go:275-303`), so the EPSS feed can churn without ever completing on a loaded DB. The work is the slowness: it is the dominant per-day write volume in the whole ingest subsystem and it is 100% serialized.

**Impact:** Reachability: runs every 24h, unconditionally when a new score file is published. Frequency: 250k inner iterations per run. Per-occurrence cost: a full transaction round-trip + advisory lock + commit. Aggregate: CRITICAL — this single loop dominates EPSS ingest wall-clock and risks never finishing under the job timeout.

**Confidence:** Strong-static (row count documented in the adapter header; loop structure and per-row tx are explicit in source).

**Effort:** Contained + low-to-moderate. A bounded worker pool (e.g. `errgroup` with `SetLimit(N)`, N ≈ 8–16) fanning out `applyRow` calls keyed by CVE ID is a localized change to `Apply`; the only cross-cutting concern is ensuring the shared `*sql.DB` pool has N free conns (see the pool-exhaustion finding below).

**Verification plan + correctness guard:**
- *Independence proof:* Each `applyRow` call targets exactly one `cve_id`, takes `pg_advisory_xact_lock(CVEAdvisoryKey(cveID))`, and writes only that CVE's row in `cves` / `epss_staging`. EPSS scores are explicitly excluded from `material_hash` (CLAUDE.md §5.3), so there is no merge-ordering or hash-recompute dependency between rows. The CSV has one row per CVE (it is a score table), so two in-flight goroutines never contend on the same advisory key in normal data — and if a duplicate row ever appeared, the advisory lock already serializes it correctly. No shared mutable Go state is touched inside `applyRow` (it takes `db`, `cveID`, `score`, `asOfDate` by value). This is a clean fan-out target.
- *Race guard:* (1) Keep `cr.ReuseRecord = true` semantics intact — `cveID` is already `strings.Clone`d at `:212` before dispatch, but `score`/`asOfDate` must be captured into per-iteration locals before the goroutine starts (Go 1.22+ loop-var semantics make this safe, but verify). (2) Preserve the existing per-row "log-and-continue" error handling (`:227-231`) per goroutine so one bad row doesn't abort the batch. (3) Use `errgroup.WithContext` so ctx cancellation (job timeout / shutdown) propagates and stops dispatch. (4) Benchmark: capture wall-clock for a fixed 250k-row fixture at N=1 (today) vs N=8/16 against a real Postgres (testcontainers); confirm the advisory-lock contention doesn't invert the gain (it won't — keys are distinct per row).

---

### [MAJOR] All seven non-EPSS feeds share one `feed_ingest` queue at concurrency 1, serializing independent feeds

**Location:** `cmd/cvert-ops/main.go:186-188` and `:437-439` — `workerPool.Register("feed_ingest", ...)`; `Register` pins concurrency to 1 (`internal/worker/pool.go:77-79`). Scheduler enqueues nvd, mitre, kev, ghsa, osv, msrc, redhat all onto `feed_ingest` (`internal/ingest/scheduler.go:44-52`, `internal/ingest/feeds.go:83-88`).

**Problem:** `runQueue` builds a semaphore of size `maxConc` (`pool.go:150`), and `feed_ingest` gets `maxConc = 1`. So at most one feed job runs at a time across the entire process. These seven feeds are completely independent data sources (different upstreams, different rate limiters, different cursors). When a large feed is mid-run — e.g. OSV downloads `all.zip` and parses every advisory (`osv/adapter.go:104-119`), or NVD walks 120-day windows page by page with a 6s/req limiter (`nvd/adapter.go:86,105`) — every other due feed sits in the queue behind it. A single slow NVD backfill (years of history at 6s/page) blocks KEV (which is tiny and time-sensitive — known-exploited vulns), GHSA, MSRC, and Red Hat from ingesting at all. The per-feed rate limiters and per-feed circuit breakers (`ingest/handler.go:84-93`) are built for concurrent operation but never get the chance because the queue is the bottleneck.

**Impact:** Reachability: every scheduler tick (1 min) that finds >1 due feed. Frequency: continuous during any large-feed run, especially first-boot backfill where all feeds are due simultaneously. Per-occurrence cost: full head-of-line blocking — a multi-hour NVD backfill stalls all other feeds for hours. Aggregate: MAJOR — directly inflates freshness latency for time-sensitive feeds (KEV) and serializes the whole ingest fan-in.

**Confidence:** Strong-static (registration concurrency and semaphore sizing are explicit; scheduler routes all built-in feeds to the one queue).

**Effort:** Localized + low. Either `RegisterWithConcurrency("feed_ingest", handler, N)` (the API already exists, `pool.go:91-99`) with N ≈ number of feeds, or give heavy feeds their own queues. Bounded by DB-pool headroom (next finding).

**Verification plan + correctness guard:**
- *Independence proof:* Distinct feeds write distinct `cve_sources.source_name` rows and merge into the canonical corpus through the per-CVE advisory lock (`merge/pipeline.go:60`). Two feeds touching the *same* CVE are serialized by that lock, not by the queue — so concurrency at the queue level is already safe by construction. The scheduler dedups per feed via the `lockKey = "feed:" + feedName` on `EnqueueJob` (`scheduler.go:157-159`), so raising queue concurrency cannot cause two concurrent jobs *for the same feed* (which would race on a single cursor) — it only lets *different* feeds run in parallel. That is exactly the independence we need.
- *Race guard:* (1) Confirm the per-feed `EnqueueJob` lockKey actually prevents same-feed double-claim at concurrency >1 (read `ClaimJob` / lock_key semantics in the store; the scheduler relies on it). (2) The lazily-created circuit-breaker map in `handlerWithStore` is already mutex-guarded (`handler.go:81-93`) — safe under concurrent handler invocations. (3) Cap N at DB-pool headroom so parallel merges don't exhaust connections. (4) Measure first-boot backfill: time-to-first-KEV-success at concurrency 1 vs N.

---

### [MAJOR] Realtime alert path adds two serial DB round-trips per merged patch, inline in the fetch→merge loop

**Location:** `internal/ingest/handler.go:163-211` — inside `for _, patch := range result.Patches`: `GetCVEMaterialHash` before merge (`:169`), `mergeFn` (`:181`), `GetCVEMaterialHash` again after merge (`:194`), then `EvaluateRealtime` (`:202`) — all sequential, per patch, single-threaded.

**Problem:** When the handler is wired with alerts (the production path, `main.go:188`), each patch incurs *two extra* standalone DB queries (`GetCVEMaterialHash`) bracketing the merge, plus a synchronous `EvaluateRealtime` when the hash changed — and the whole patch loop is serial. For a large NVD page (up to 2000 patches, `nvd/adapter.go:44`) or an OSV full run (tens of thousands of advisories), that's 2× extra round-trips per item layered on top of the already-serial merge, none of it overlapped with the next patch's merge. The pre-merge hash read in particular is a separate query that could be folded into the merge transaction's `UPSERT ... RETURNING` (the merge already computes the new hash at `merge/pipeline.go:136`), eliminating one round-trip per patch entirely.

**Impact:** Reachability: every feed run in production (alerts always wired). Frequency: per patch — thousands per large page. Per-occurrence cost: 2 extra DB round-trips + a possibly-empty realtime eval, all serial. Aggregate: MAJOR on large feeds; the duplicated standalone hash reads are pure overhead on the hottest path.

**Confidence:** Strong-static (the two `GetCVEMaterialHash` calls and their serial placement are explicit).

**Effort:** Contained. Folding the hash-change signal into the merge return (`merge.Ingest` returns `(hashChanged bool, err error)`) removes both standalone reads; that touches the `merge.Store`/`MergeFunc` signature (cross-package, hence Contained not Localized). Decoupling `EvaluateRealtime` onto a bounded background worker is a further step.

**Verification plan + correctness guard:**
- *Independence proof / why this is safe:* The merge transaction already holds the per-CVE advisory lock and computes `materialHash` at `pipeline.go:136`; returning whether the `IS DISTINCT FROM` hash guard fired makes the post-merge read redundant and the pre-merge read unnecessary. This is a *de-duplication* of reads, not new parallelism, so no new race is introduced for that part. For decoupling `EvaluateRealtime`: realtime eval reads a single CVE by ID and is already a separate concern; if moved to a background dispatch it MUST use `context.WithoutCancel` (the handler's pattern, cf. `pool.go:171`) and a bounded channel/pool so a slow evaluator can't unbounded-spawn goroutines or be cancelled when the job completes.
- *Race guard:* If `EvaluateRealtime` is backgrounded, bound concurrency (channel or `errgroup.SetLimit`) and ensure ordering is irrelevant — realtime eval per CVE is idempotent given `alert_events` UNIQUE `(org_id, rule_id, cve_id, material_hash)` + `ON CONFLICT DO NOTHING` (CLAUDE.md), so out-of-order evals across different CVEs are safe. Do NOT background it without that guard. Benchmark a 2000-patch NVD page with/without the folded hash read.

---

### [MINOR] Synchronous per-page cursor persist serializes a DB write into the fetch loop

**Location:** `internal/ingest/handler.go:224-236` — `UpsertFeedSyncState` after every page, in-line, blocking the next `adapter.Fetch`.

**Problem:** After each page the handler does a blocking sync-state UPSERT for crash-recovery checkpointing before fetching the next page. For a true paginator (NVD) this serializes a DB round-trip between every HTTP page. It is intentional (crash recovery), and relative to the 6s NVD rate-limit wait it's negligible — but on a fast-paginating feed with an API key (0.6s/req) the synchronous checkpoint write is a non-trivial fraction of per-page time, and it blocks the pipeline rather than overlapping with the next fetch's rate-limit wait.

**Impact:** Reachability: every page of every paginating feed. Frequency: per page. Per-occurrence cost: one DB round-trip. Aggregate: MINOR — dominated by rate-limit waits today; only matters if/when feeds run with high-rate API keys. Recording for completeness, not urgent.

**Confidence:** Heuristic (cost depends on rate-limit config; checkpoint is correctness-motivated).

**Effort:** Localized, but **not recommended** to change naively — the synchronous checkpoint is the crash-recovery contract. Any async/batched checkpoint must preserve "cursor never advances past durably-merged data." Flagging, not prescribing.

**Verification plan:** Only act if profiling shows checkpoint writes are a measurable fraction of high-rate-key paginating runs. Correctness guard: checkpoint must remain ≤ last successfully-merged page; do not move it after an un-awaited write.

---

## DEFEND summary (lock contention / blocking-in-lock / pool exhaustion)

- **Advisory lock granularity is correct.** The merge pipeline holds `pg_advisory_xact_lock` per-CVE (`pipeline.go:60`), and EPSS uses the *same* key (`epss/adapter.go:260`, `advisory.go:36`). There is **no** coarse global lock — keys are CVE-scoped, so cross-CVE writers don't contend. No finding here; this is the right design and it's *why* the two parallelization findings above are safe.
- **No blocking HTTP call is held inside any lock.** Fetch (HTTP) happens entirely outside the merge transaction; the advisory lock is acquired only after the patch is already in hand (`handler.go` fetch loop → `merge.Ingest` tx). Good.
- **DB pool vs ingest concurrency — watch before raising parallelism.** The shared `*sql.DB` wraps the pgxpool with `DBMaxConns` default 25 (`config.go:20`, `main.go:750`). Both proposed parallelizations (EPSS fan-out, multi-feed concurrency) draw from this same pool, *and* each merge already nests multiple statements per transaction. Raising EPSS fan-out to N and feed concurrency to M simultaneously could request up to N+M concurrent conns against 25. Any fix MUST size fan-out below available pool headroom (and the startup check at `main.go:786-792` only warns about Postgres `max_connections`, not app-side saturation). This is the dependency to respect, not a standalone defect.
- **Context propagation on long ingests is handled.** Jobs run under `context.WithTimeout(context.WithoutCancel(ctx), maxJobDuration)` (`pool.go:171`) so a long ingest is detached from shutdown but capped — correct pattern. The EPSS rate-limiter `Wait` is additionally capped at 5min (`epss/adapter.go:134`). No goroutine-leak or missing-cancellation finding in the ingest path.
- **Circuit-breaker map is mutex-guarded** (`handler.go:81-93`) — safe for the concurrent-handler scenario the multi-feed fix would introduce.

---

## Suspected Bugs (for follow-up)

- **EPSS `maxJobDuration` mismatch (record, don't chase):** If the serial EPSS loop genuinely exceeds 10 minutes (likely on a loaded DB per the CRITICAL finding), the job ctx is cancelled mid-loop. `applyRow` errors are caught and `continue`d (`adapter.go:227-231`), so a cancelled ctx would make *every remaining row* fail-and-skip, then `Apply` returns a *new cursor* as if successful (`adapter.go:234-239`) and the handler persists it (`ingest/epss.go:85-95`) — silently marking a partial run as complete and skipping re-download next day via the score_date short-circuit (`adapter.go:121-128`). This is a correctness/data-completeness bug downstream of the perf issue; fixing the serialization removes the trigger, but the swallow-cancellation-as-success path is worth a separate look. Not a concurrency-perf defect per se.
