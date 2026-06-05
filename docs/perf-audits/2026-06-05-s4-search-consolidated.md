---
run_schema_version: 1
run_id: 2026-06-05-s4-search
date: 2026-06-05T01:25:00Z
scope: "S4 — Search, CVE read & watchlist (api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go, store/{saved_search,watchlist}.go)"
methodology:
  skill: performance-audit-cycle
  plugin_version: superpowers-plus@0.2.0 (vendored; version per source repo)
dispatch: { model_requested: "opus (latest; Claude Code Agent tool)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack:
  - { ecosystem: go, framework: "huma/v2", version: 2.37.3 }
  - { ecosystem: go, framework: "chi/v5", version: 5.2.5 }
  - { ecosystem: go, framework: "pgx/v5 + database/sql adapter + squirrel", version: "5.9.2 / 1.5.4" }
currency_briefs:
  - { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); huma/pgx third-party — Heuristic where index silent" }
lanes_run: [algorithmic, memory, data-access, concurrency, idiom-currency, cost-map]
lanes_skipped: { payload-startup: "JSON API responses covered under memory; no bundle/startup surface (frontend is S7)", dynamic: "no Docker/testcontainers + no corpus locally" }
finding_counts:
  by_impact: { critical: 1, major: 6, minor: 6 }
  by_lane: { algorithmic: 4, memory: 4, data-access: 5, concurrency: 3, idiom-currency: 3 }
  suspected_bugs: 3
regression: { prev_run_id: null, new: 13, persisting: 0, resolved: 0 }
---

# Performance Audit (consolidated + validated) — S4 Search, CVE read & watchlist

**Scope:** api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go, store/{saved_search,watchlist}.go (+ cves/watchlist/saved_searches SQL + DDL adjacent)
**Stack:** huma/v2 2.37.3 · chi/v5 · pgx/v5 via `database/sql` adapter + squirrel · FTS GIN. **Verification:** static-only. **Regression vs none:** 13 new.

**Scope-brief correction (recorded per the method):** the scope brief assumed *facet aggregation over the
corpus* as a hot region. Three lanes independently verified **no facet/`COUNT(*)`-over-corpus query
exists** in current code (faceting is a PLAN feature, not implemented), and the list path uses the
`limit+1` trick (no separate total-count scan, no OFFSET). The lanes correctly **refused to manufacture**
a facet finding — flagged as the most likely *future* hot spot instead. List responses also already stream
(`json.NewEncoder`), so the whole-buffer marshal footgun is absent on the chi handlers.

## Critical Findings

### P1. CVE list/search keyset pagination has no composite index for its `(date_modified_canonical, cve_id)` cursor
**Lanes:** data-access (critical), algorithmic (major), cost-map (agreement ×3)  **Location:** keyset query `internal/store/cve.go:194-205` & `internal/store/dsl_executor.go:142-156`; index `migrations/000002_create_cve_core.up.sql:45`
**Fingerprint:** `data-access:cves.sql:keyset:missing-composite-index`  **Status:** new
**Problem:** The query seeks/sorts on the **row-value** `(date_modified_canonical, cve_id) < (?, ?)` with `ORDER BY date_modified_canonical DESC, cve_id DESC`, but the only index is single-column `cves_date_modified_canonical_idx`. **Validated:** confirmed — the row-value keyset is correctly written (`cve.go:197-203`), but the composite index it needs does not exist. The single-column index serves the leading column, leaving the `cve_id` tiebreak **unindexed within each same-timestamp cluster**; bulk ingest/merge stamps many CVEs with near-identical `date_modified_canonical`, so the cluster (and the per-page sort/heap-fetch) is unbounded.
**Impact:** reachability = the **default browse path + every search page + every saved-search execution** over a ~250k corpus; per-occurrence = degrades from O(log N + limit) to a cluster-proportional scan+sort. **Confidence:** Strong-static  **On cost map:** yes (High)
**Effort:** **Localized, lowest-effort/highest-value quick win** — one `CREATE INDEX CONCURRENTLY … (date_modified_canonical DESC, cve_id DESC)` migration, no code change. The same single-column-vs-composite mismatch also affects the `alert_events` and `watchlists` keyset indexes (data-access lane) — fix them in the same migration.
**Verification plan:** `EXPLAIN (ANALYZE)` the keyset query before/after on a same-timestamp cluster (Index Scan vs Sort); correctness guard = pagination returns the same totally-ordered sequence (no dup/skip across pages).

## Major Findings

### P2. CVSS/EPSS range filters are non-sargable and unindexed (full corpus scan for score-only searches)
**Lanes:** data-access, algorithmic  **Location:** `internal/store/cve.go:141-147,186-192`
**Fingerprint:** `data-access:cve.go:cvss-epss-range-nonsargable`  **Status:** new
**Problem:** `COALESCE(cvss_v4_score, cvss_v3_score) >= ?` and `COALESCE(epss_score, sentinel) [<=>] ?` defeat any index, and there is no index on the CVSS columns or `epss_score`. A "CVSS ≥ 7" / "EPSS ≥ 0.5"-only search (no FTS term to narrow first) full-scans the 250k corpus. **Validated:** confirmed at cited lines.
**Impact:** full scan per score-only filtered search. **Confidence:** Strong-static  **Effort:** Contained — a functional index on `COALESCE(cvss_v4_score, cvss_v3_score)` and an index on `epss_score`, or restructure the predicate to be sargable.
**Verification plan:** EXPLAIN shows index usage; guard = identical result set.

### P3. `GetCVEDetail` issues 4 sequential round-trips where 3 child fetches are independent
**Lanes:** concurrency, data-access, idiom-currency, cost-map (agreement ×4)  **Location:** `internal/store/cve.go:49-73` (via `internal/api/cves.go:411`)
**Fingerprint:** `concurrency:cve.go:GetCVEDetail:serial-child-queries`  **Status:** new
**Problem:** The most-viewed endpoint fetches CVE → references → packages → CPEs one RTT at a time; the three child queries are independent single-key lookups on the RLS-free **global** corpus (no per-tx `SET LOCAL` to coordinate), so they can pipeline. **Validated:** confirmed.
**Impact:** RTT × 4 where RTT dominates on remote pooled Postgres; interactive path. **Confidence:** Strong-static  **Effort:** Contained — `pgx.Batch` (one round-trip) or bounded `errgroup` on separate pooled conns. **Blast radius:** each parallel query needs its own conn (don't share a tx across goroutines); safe because the corpus is global/RLS-free here.
**Verification plan:** round-trip argument (4 → ~1 via Batch); guard = identical detail payload.

### P4. Hot CVE search/DSL reads use the `database/sql` adapter + `lib/pq` array decode instead of the pgx-native fast path
**Lanes:** idiom-currency, memory  **Location:** `internal/store/cve.go:210-228`, `internal/store/dsl_executor.go:51-79,243-261` (the pgx pool `s.pool` is already exposed)
**Fingerprint:** `idiom-currency:cve.go:database-sql-vs-pgx-native`  **Status:** new
**Problem:** `SearchCVEs`/`scanDSLRows` hand-scan 21 fields per row through the stdlib `any`-boxing layer and text-parse `cwe_ids` via `pq.Array`; `pgx.CollectRows` + `RowToStructByName` over `s.pool` skips both. Highest-reachability read path. **Validated:** confirmed (the adapter is `stdlib.OpenDBFromPool`; `s.pool` exists).
**Impact:** per-row boxing + array text-parse on every search result row. **Confidence:** Strong-static (gap), Heuristic (magnitude — pgx internals outside the index). **Effort:** Contained — route the hot read queries through `s.pool` with pgx row collection. **Blast radius:** preserve scan semantics + nullability; coexists with the simple-protocol mode (pgx native still works).
**Verification plan:** alloc/CPU argument; guard = identical scanned rows incl. NULL handling.

### P5. `GET /cves/{id}/sources` materializes all sources' full raw JSON with no count/size cap
**Lanes:** memory, cost-map  **Location:** `internal/api/cves.go:497-537`, `internal/store/cve.go:84-86`, `internal/store/queries/cves.sql:69`
**Fingerprint:** `memory:cve.go:GetCVESources:unbounded-raw-json`  **Status:** new
**Problem:** `SELECT *` with no `LIMIT`; each row carries the entire per-source normalized upstream blob (8+ feeds, tens of KB each), all resident (DB buffers + `[]CveSource` + re-allocated `[]CVESourceResponse`) before serialization. **Validated:** confirmed.
**Impact:** unbounded peak response memory on a drill-down endpoint. **Confidence:** Strong-static  **Effort:** Localized — cap source count / paginate, project only needed columns, stream.
**Verification plan:** peak-memory argument; guard = response shape unchanged within the cap.

### P6. `ListWatchlists` LEFT JOINs all items + GROUP BY/COUNT per page just to compute `item_count`
**Lanes:** data-access, cost-map  **Location:** `internal/store/watchlist.go:107-151`
**Fingerprint:** `data-access:watchlist.go:ListWatchlists:groupby-count-fanout`  **Status:** new
**Problem:** A fan-out join + HashAggregate over all items to compute `item_count` for ≤20 watchlists per page — scales with total item count, not page size. **Validated:** confirmed.
**Impact:** aggregate-on-read proportional to item count. **Confidence:** Strong-static  **Effort:** Localized — correlated/`LATERAL` count subquery, or drop the count from the list view.
**Verification plan:** EXPLAIN (no HashAggregate over all items); guard = identical counts.

### P7. CVE list/search over-fetches 21 columns; the list DTO consumes ~14
**Lanes:** memory, algorithmic  **Location:** `internal/store/dsl_executor.go:25-79` (`cveColumns`/`scanCVERow`), `internal/api/cves.go:161`
**Fingerprint:** `memory:dsl_executor.go:cveColumns:over-fetch`  **Status:** new
**Problem:** Fetches/scans two CVSS vector strings, three `*_source` strings, `material_hash`, etc. that `CVEItem` never reads — ~6 wasted `sql.NullString` allocs × up to 101 rows/page on the hottest endpoint, plus an extra DB read of TOAST-able vector columns. **Validated:** confirmed.
**Impact:** per-row over-fetch × page × request rate. **Confidence:** Strong-static  **Effort:** Localized — a list-projection column set distinct from the detail set.
**Verification plan:** column-count argument; guard = list DTO fields unchanged.

## Minor Findings

### P8. FTS combined with date-ordered keyset sorts the whole match set (no cap)
**Lane:** data-access, cost-map  **Location:** `internal/store/cve.go:128-184`  **Fingerprint:** `data-access:cve.go:fts-sort-whole-matchset`  **Status:** new — GIN FTS is used correctly (no ILIKE fallback), but a broad single-word term matches a large fraction of the corpus and the `date` ORDER BY sorts it all per page. Contained (the composite index from P1 helps; consider a rank-bounded path for broad terms).

### P9. DSL post-filter re-materializes the whole result slice by value (executor double-copy) **[shared with S2 P8 — dsl_executor.go]**
**Lane:** memory, algorithmic  **Location:** `internal/store/dsl_executor.go:200-211`  **Fingerprint:** `memory:dsl_executor.go:postfilter-double-copy`  **Status:** new — `filtered` already holds pointers; `make([]generated.CVE,…)` copies each wide struct again. Localized. (Same code is exercised by the S2 alert sweep — dedupe in roll-up.)

### P10. `cveToItem` takes `generated.CVE` by value (double wide-struct copy per row)
**Lane:** memory  **Location:** `internal/api/cves.go:161` (called `:384`, `saved_searches.go:457`)  **Fingerprint:** `memory:cves.go:cveToItem:by-value-copy`  **Status:** new — range-by-value + by-value param copies the ~20-field struct twice per list row. Localized (take a pointer).

### P11. `ListSavedSearches` orders by `updated_at DESC` with no supporting index and no keyset
**Lane:** algorithmic  **Location:** `internal/store/queries/saved_searches.sql:14-25`  **Fingerprint:** `algorithmic:saved_searches.sql:no-index-order`  **Status:** new — bounded by `LIMIT 200`/org so near-non-finding; the lone non-keyset list path. Localized.

### P12. Ecosystem/package `EXISTS` filter has no `(ecosystem, package_name)` index **[related to S2 P6 — shared compiler predicates]**
**Lane:** algorithmic, data-access  **Location:** `internal/store/cve.go:141-176`  **Fingerprint:** `data-access:cve.go:exists-ecosystem-pkg-noindex`  **Status:** new — the `cve_affected_packages` EXISTS is indexed only on `cve_id`, not the filtered `(ecosystem, package_name)`, so an ecosystem/package filter without FTS seq-scans. Localized (add the index).

### P13. `GET /cves` (huma) buffers the page to marshal while sibling list handlers stream
**Lane:** idiom-currency  **Location:** `internal/api/cves.go:315-396` (huma, buffered) vs `internal/api/contract.go:18-24` (streaming)  **Fingerprint:** `idiom-currency:cves.go:huma-buffered-list`  **Status:** new — idiom inconsistency; payload ≤101 small items so **no change recommended** (huma buffering buys Content-Length + the typed contract). Awareness only.

## DEFEND / cross-cutting

### P14. Expensive FTS/EXISTS searches have no per-request HTTP write deadline — and the `http.TimeoutHandler` the project requires is absent everywhere
**Lanes:** concurrency (DEFEND)  **Location:** `cmd/cvert-ops/main.go:306` (comment), `internal/api/server.go`; the only `TimeoutHandler` reference in the repo is the **comment** claiming it is applied
**Fingerprint:** `concurrency:api:missing-timeouthandler`  **Status:** new
**Problem:** `WriteTimeout` is omitted globally (correct, per CLAUDE.md) **but** the per-handler `http.TimeoutHandler` that CLAUDE.md mandates ("apply per non-streaming handler via `http.TimeoutHandler`") is **not implemented anywhere** — verified: the sole match is the false comment at `main.go:306`. A slow `SearchCVEs`/EXISTS query pins 1 of 25 pool connections for up to the 14s `statement_timeout`; a handful saturate the pool. **Validated:** confirmed by grep — no `http.TimeoutHandler` in `internal/api` or `cmd`.
**Impact:** availability — pool exhaustion under a few slow/expensive searches; **also a plan-compliance gap** (CLAUDE.md HTTP-server requirement). **Confidence:** Strong-static  **Effort:** Contained — wrap non-streaming handlers in `http.TimeoutHandler` (or a chi timeout middleware) as the project already intends.
**Verification plan:** a slow-query test asserting the handler returns 503/timeout and frees the conn before `statement_timeout`; guard = streaming endpoints excluded.

## Execution Cost Map (architectural awareness)
> Full map in `2026-06-05-s4-search-cost-map.md`. Two always-present dominant costs: the **FTS GIN scan**
(text searches) and the **filtered keyset sort** (all searches, P1). Everything else is page-bounded
(≤101 rows). `GET /cves*` is global/RLS-free (skips the per-request `SET LOCAL` round-trip); org-scoped
reads pay a ~3-statement transaction floor. **No facet/COUNT/OFFSET scan exists today** (future hot spot).

## Measurability
Search/detail latency is observable via standard HTTP metrics; the index win (P1) needs `EXPLAIN ANALYZE`
on a clustered timestamp window to demonstrate. Recommend a slow-query log threshold.

## Suspected Bugs (for follow-up — NOT addressed here)
> Kickoff: `docs/perf-audits/2026-06-05-s4-search-bug-hunt-kickoff.md`.
- **SB1. `main.go:306` comment claims `http.TimeoutHandler` is applied per-handler — it is not** (see P14). Misleading comment **and** missing protection.
- **SB2. (verify intent) EPSS range `COALESCE` sentinels exclude NULL-EPSS rows when a filter is set, while the comment says they prevent NULL rows being dropped** — `internal/store/cve.go:186-192`. Excluding NULL-EPSS rows from an "EPSS ≥ x" filter is likely the *desired* behavior, so the **code is probably right and the comment is wrong** — confirm intent.
- **SB3. Three non-interchangeable cursor base64 codecs** — the saved-search DSL cursor uses padded `base64.URLEncoding` (`dsl_executor.go:93,102`) while the API-layer codecs use `RawURLEncoding`; a cursor minted by one path may not decode on another. Verify cursor interchange.

---
**Disposition:** all 13 findings default to **FIX**; P1 is the marquee quick win (one index migration). P13
is documented as awareness (no change). No severity/effort deferral. 3 suspected bugs handed off (P14's
missing-`TimeoutHandler` is both a finding and a plan-compliance gap worth raising).
