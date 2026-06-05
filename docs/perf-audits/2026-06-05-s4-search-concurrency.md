# S4 Search / CVE-read / Watchlist — concurrency & parallelization lane

ABOUTME: Performance audit of the S4 hot read path (CVE search/detail, saved searches, watchlists,
ABOUTME: alert events) for the concurrency lane — both EXPLOIT (under-parallelized) and DEFEND (blocking/contention).

Scope read (actual source): `internal/api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go`,
`internal/store/{cve,saved_search,watchlist,dsl_executor,store,timeout}.go`,
`internal/store/queries/{cves,watchlist}.sql`, plus `cmd/cvert-ops/main.go` (pool + server setup)
and `internal/api/server.go` (middleware chain), `internal/alert/cache.go` (shared cache sync).

Lane: **concurrency & parallelization**, both directions. The CVE corpus is global/shared (no RLS on
`cves` and its child tables); org-scoped reads (watchlists, saved searches, alert events) use
`withOrgTx`/`withOrgRawTx` (one `SET LOCAL app.org_id` per transaction). Pool is `DBMaxConns=25`
(`main.go:746` also sets a global `statement_timeout` via `RuntimeParams`). HTTP server omits
`WriteTimeout` globally.

---

## Findings

### MAJOR — `GetCVEDetail` issues four DB round-trips serially on the RLS-free global corpus when three are independent and parallelizable
**Location:** `internal/store/cve.go:49-73` (`GetCVEDetail`); consumed by `getCVEHandler` `internal/api/cves.go:411-477`
**Problem:** The CVE detail endpoint runs four queries strictly in sequence: `GetCVE` (canonical row),
then `GetCVEReferences`, `GetCVEAffectedPackages`, `GetCVEAffectedCPEs`. Each is a separate network
round-trip on `s.q` (the shared `*sql.DB`). The three child-table fetches are mutually independent —
they share no state, have no ordering dependency, and all key purely on `cve_id` (`cves.sql:151-158`).
Only `GetCVE` must run first (to return 404 and to know the CVE exists). The three child queries are
executed one-after-another, so per-request latency is `rtt(cve) + rtt(refs) + rtt(pkgs) + rtt(cpes)`
when it could be `rtt(cve) + max(rtt(refs), rtt(pkgs), rtt(cpes))`.

Crucially, these tables are **global and RLS-free** — `cves`, `cve_references`, `cve_affected_packages`,
`cve_affected_cpes` carry no `org_id` and no `SET LOCAL` requirement (the methods call `s.q.*` directly,
not through `withOrgTx`). That removes the usual blocker to parallelizing under this codebase's RLS model:
each parallel query can run on its own pooled connection via the shared `s.db`/`s.q` with **no** per-tx
`SET LOCAL app.org_id` to coordinate, and there is no transaction that must be shared across goroutines.
This is the cleanest parallelization candidate in the slice.

**Impact:** Reachable on every CVE detail page view — an interactive, high-frequency endpoint. Per
occurrence: collapses 3 serial child round-trips into 1 round-trip's worth of wall-clock latency,
saving ~2 RTTs per detail request. Over a 250k-corpus product with interactive browsing this is a
steady, broad latency win on a core navigation path. Cost is 3 concurrently-held pooled connections
for the brief fetch window instead of 1 held longer.
**Confidence:** Strong-static — independence is provable from the SQL (single-key lookups, no shared
writes); the serial structure is explicit in the function body.
**Effort:** Localized (rewrite one function body with `errgroup.WithContext`; handler signature
unchanged). Add low-effort.
**Verification plan:** Argument: total latency drops from sum to first + max of the three child queries;
allocation unchanged (same result slices). Guard: existing `getCVEHandler` integration test pinning the
full detail payload (refs/pkgs/cpes ordering and 404-on-missing) must stay green — ordering is already
deterministic via each query's `ORDER BY`, so parallel issue does not change output. Add a test asserting
that a query error in any one child still surfaces (errgroup propagation) and that a missing CVE still
short-circuits before any child query runs. Cap the concurrency at 3 (fixed fan-out, far below
`DBMaxConns=25`); document the pool-headroom note so this never grows unbounded.

---

### MINOR — `getCVESourcesHandler` does an existence pre-check (`GetCVE`) serially before fetching sources, when a single sources query plus emptiness check would do
**Location:** `internal/api/cves.go:497-538` (`GetCVE` then `GetCVESources`); store `cve.go:19-28,84-86`
**Problem:** The sources endpoint runs `GetCVE` purely to decide 404-vs-empty-list, then runs
`GetCVESources`. Two serial round-trips on the global corpus. The existence check and the sources fetch
are independent (both key on `cve_id`) and could be issued concurrently; or, since a CVE with zero source
rows is effectively non-existent in this corpus (every CVE is built from `cve_sources` by the merge
pipeline — `cves.sql:69-70`), the pre-check is arguably redundant and one query suffices. Lower impact
than detail because `/sources` is a secondary drill-down, not the primary detail view.
**Impact:** Reachable only when a client opens the per-source comparison view — lower frequency than the
detail page. Saves one RTT per such request.
**Confidence:** Heuristic — the "zero sources ⇒ treat as 404" equivalence depends on the merge invariant
(no `cves` row exists without ≥1 `cve_sources` row); parallelizing the two queries is unconditionally
safe and is the conservative fix.
**Effort:** Localized.
**Verification plan:** If parallelizing: same correctness guard as detail (errgroup propagation, both
queries independent). If collapsing to one query: add a test that a CVE with no source rows returns 404,
to pin the merge invariant the optimization relies on. Argument: one fewer RTT per request, no extra
allocation.

---

### MINOR (DEFEND) — Expensive FTS / EXISTS search queries run with no per-request HTTP write deadline; only the 14s DB `statement_timeout` bounds a connection held from the 25-slot pool
**Location:** server: `cmd/cvert-ops/main.go:308-314` (`WriteTimeout` omitted, no `http.TimeoutHandler`);
chain: `internal/api/server.go:180-241` (no timeout middleware around the huma sub-router);
query: `internal/store/cve.go:124-229` (`SearchCVEs` FTS join + `EXISTS` package subqueries on a 250k corpus)
**Problem:** `main.go:306` claims "WriteTimeout … applied per-handler via `http.TimeoutHandler`," but
`http.TimeoutHandler` is not used anywhere in the API package (verified by grep across
`internal/api/**`). The global server sets `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout` but no
`WriteTimeout`, and no per-handler timeout wrapper exists. For a slow `SearchCVEs` (FTS `@@` against
`cve_search_index` joined to a 250k `cves`, plus per-row `EXISTS` ecosystem/package subqueries — the
heaviest read in the slice), the only thing that frees the held pooled connection is the DB-side
`statement_timeout` (`main.go:746`, default 14s). With `DBMaxConns=25`, a burst of slow searches (or a
client that disconnects mid-scan — note `s.db.QueryContext(ctx, …)` does pass `r.Context()`, so client
cancel *does* propagate to the driver) can pin a meaningful fraction of the pool for up to the statement
timeout. The request goroutine itself is not the bottleneck; the **pooled connection** it holds is.
This is a defensive gap, not an active hotspot: `statement_timeout` + context propagation bound the worst
case to 14s and to client-lifetime, which is why this is MINOR rather than MAJOR.
**Impact:** Reachable under adversarial or pathological-query load on the search endpoint; per occurrence
a slow query holds 1 of 25 pool slots for up to ~14s. Aggregate risk is connection-pool starvation under
a thin margin, not steady per-request cost.
**Confidence:** Strong-static for the missing wrapper (grep-confirmed absent despite the comment);
Heuristic for the pool-starvation severity (depends on real query latency distribution, which cannot be
measured here).
**Effort:** Contained — wrap the huma sub-router (or the expensive GET routes) in
`http.TimeoutHandler` with a write deadline below the 14s `statement_timeout`, so the HTTP layer sheds the
client before the DB does, and align the per-route timeout with the DB cap. Touches `server.go` route
wiring. The stale comment at `main.go:306` should also be corrected (recorded under Suspected Bugs).
**Verification plan:** Argument: a per-request HTTP write deadline caps goroutine + response-buffer
lifetime independent of DB behavior and gives a single coherent ceiling. Guard: add a test that a handler
exceeding the deadline returns 503/timeout and that normal fast requests are unaffected; confirm streaming
endpoints (if any in this slice — none of S4's are streaming) are not wrapped.

---

## Examined and found NOT a problem (to bound the search)

- **List endpoint (`listCVEsHandler` / `SearchCVEs`)** uses keyset pagination with **no** companion
  total-count or facet query — there is no list+count+facets fan-out to exploit here (unlike the classic
  list-page pattern the lane brief anticipates). Single query per page; correct.
- **Org-scoped list reads** (`ListWatchlists`, `ListWatchlistItems`, `ListSavedSearches`,
  `ListAlertEvents`, `ListAlertRules`) are each a single query inside one `withOrgTx`/`withOrgRawTx`.
  They cannot be naively parallelized across goroutines because `SET LOCAL app.org_id` is
  per-transaction and a `*sql.Tx` is not goroutine-safe — and there is nothing to parallelize anyway
  (one query each). `ListWatchlists` folds the item count into the list via `LEFT JOIN … COUNT … GROUP BY`
  (`watchlist.go:107-151`) rather than N+1 per-row counts — already the right call.
- **`GetWatchlist`** runs two queries (`GetWatchlist` + `CountWatchlistItems`) inside one org tx. These
  must share the org-scoped transaction for RLS, so they cannot be split across connections without two
  `SET LOCAL` round-trips; the count is cheap and the win would be marginal. Not worth it. (The list path
  already avoids this via the JOIN above.)
- **`updateWatchlistHandler`** re-fetches the row after update to include `item_count`
  (`watchlists.go:393-399`) — an extra round-trip, but on a cold write path (PATCH), not the hot read
  path this lane targets. Out of scope (cold path, calibration exclusion).
- **`alertCache` (`RuleCache`)** is a shared mutable cache but is correctly guarded by `sync.RWMutex`
  (`internal/alert/cache.go:20-21`, `Evict` at :45) — no unsynchronized shared-cache finding.
- **Transactions across response serialization:** all store methods commit/close the tx and return
  materialized slices *before* the handler serializes JSON (`writeJSON`/`writeList` run after the store
  call returns). No DB transaction or `*sql.Rows` is held open across response encoding. Correct.
- **Pool/global `statement_timeout`** is set (`main.go:746`), so no read path can hold a backend
  indefinitely — this is what downgrades the missing-`WriteTimeout` finding from MAJOR to MINOR.

---

## Suspected Bugs (for follow-up)

- **Stale/false comment in `cmd/cvert-ops/main.go:306-307`:** claims `WriteTimeout` is "applied
  per-handler via `http.TimeoutHandler`," but no `http.TimeoutHandler` exists anywhere under
  `internal/api/`. The comment documents behavior that is not implemented; either wire the handler or
  fix the comment. (Surfaced by the MINOR DEFEND finding above; recording per lane rules — not chased.)
