---
run_schema_version: 1
run_id: 2026-06-05-s10-infraglue
date: 2026-06-05T04:05:00Z
scope: "S10 — Platform/infra glue (COLD SWEEP): cmd/**, internal/{config,crypto,doctor,metrics,dbutil,log}, server/middleware/readyz/feeds/ingest"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "sonnet (Claude Code Agent tool; COLD-sweep economy)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack: [ { ecosystem: go, framework: "chi + prometheus + pgxpool", version: "go1.26.2" } ]
currency_briefs: [ { framework: go, researched_on: null, status: "COLD — idiom-currency lane not run" } ]
lanes_run: [algorithmic, memory, data-access]
lanes_skipped: { "concurrency/idiom-currency/cost-map/payload/dynamic": "COLD SWEEP / no runtime" }
finding_counts: { by_impact: { critical: 0, major: 1, minor: 5 }, by_lane: { algorithmic: 1, memory: 2, data-access: 3 }, suspected_bugs: 0 }
regression: { prev_run_id: null, new: 6, persisting: 0, resolved: 0 }
---

# Performance Audit (COLD SWEEP, validated) — S10 Platform/infra glue

**Tier:** COLD SWEEP (3 batched lanes, sonnet). **Verification:** static-only. **Regression:** 6 new.
The coldest slice — binary init, config, crypto, doctor, metrics, server wiring, remaining global
middleware. The sweep verified the things that *would* be infra footguns and found them **clean**:
**metrics label cardinality is bounded everywhere** (HTTP via `chi.RoutePattern()`, feed names, job/event
types — no unbounded Prometheus labels), no middleware opens a DB connection per request, the metrics
DB-pool collector uses in-memory snapshots, the SPA handler serves from the embedded FS (no per-request
file buffering), and the pgxpool configuration is sensible. One operationally-relevant finding + a tail of
per-request micro-allocations.

## Major Findings

### P1. `/readyz` issues two uncached DB round-trips on every probe
**Lane:** data-access  **Location:** `internal/api/readyz.go:29-63`
**Fingerprint:** `data-access:readyz.go:uncached-double-query`  **Status:** new
**Problem:** Each readiness probe runs two DB queries with no caching; the migration-version check (which never changes between probes) is the clearly wasteful one. Kubernetes/load-balancer probes hit `/readyz` frequently, so this is steady background DB load proportional to probe frequency × replicas. **Impact:** continuous, scales with deployment size. **Confidence:** Strong-static  **Effort:** Localized — cache the migration-version result (it changes only on deploy) and/or a short TTL on the liveness query; keep a real connectivity check but stop re-reading static facts.
**Verification plan:** query-per-probe argument (2 → ~0–1 cached); guard = readiness still flips correctly when the DB is actually down or migrations are behind.

## Minor Findings
- **P2** `data-access:feeds.go:list-feeds-nplus1` — `internal/api/feeds.go:63-80`: `listFeedsHandler` runs one `ListRecentFeedFetchLogs` query per feed (N+1). Bounded (~10 feeds), admin-facing. Localized (batch the recent-logs query).
- **P3** `data-access:doctor/checks.go:rlscheck-sequential` — `internal/doctor/checks.go:132-153`: `RLSCheck` issues 22 sequential `pg_class` queries (one per org-scoped table). Cold/admin-only diagnostic. Localized (one query with `WHERE relname = ANY(...)`).
- **P4** `algorithmic:middleware_apikey_query.go:query-alloc-and-scan` — `internal/api/middleware_apikey_query.go:37-49`: `r.URL.Query()` allocates a map on **every** request (incl. no-query) and the inner check is O(Q×8) `strings.ToLower` comparisons. Guard on empty `RawQuery` + a `map[string]struct{}` lookup. **Same code as S8-P4** (memory angle) — fix once. Localized.
- **P5** `memory:log_middleware.go:per-request-logger-alloc` — `internal/api/log_middleware.go:19`: `logpkg.Enrich` calls `slog.Logger.With` on every request, allocating a new `*slog.Logger` + context node + request copy even when the enriched logger is never used. Lazy construction in `FromContext`. Localized.
- **P6** `memory:metrics_middleware.go:statuswriter-itoa` — `internal/api/metrics_middleware.go:39,48`: a `statusWriter` struct + `strconv.Itoa` for the status-code label on every API request; status codes are a small fixed set → a precomputed lookup table removes the `Itoa` alloc. Localized.

---
**Disposition:** all 6 default to **FIX**. P4 is shared with S8 (fix once). The numerous confirmed-cold
infra checks (metrics cardinality, pool config, SPA serving, no per-request DB in middleware) are recorded
as calibration evidence. No suspected bugs.
