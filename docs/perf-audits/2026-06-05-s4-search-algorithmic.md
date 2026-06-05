# Perf audit — S4 "Search, CVE read & watchlist" — lane: algorithmic complexity & data structures

Date: 2026-06-05
Scope: `internal/api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go`,
`internal/store/{cve,dsl_executor,saved_search,watchlist,alert_rule}.go`,
`internal/store/queries/{cves,saved_searches,watchlist}.sql`, FTS/keyset indexes in `migrations/`.
Lane: **algorithmic complexity & data structures** — per-request work that scales with corpus/result
size, in-Go work that should be in SQL, accidental quadratics, wrong containers, recomputed work.

No runtime profiling available; nothing here is `Measured`.

---

## Summary

The hot read paths (CVE list/search, saved-search execute, alert-events list, watchlists) are
well-structured: filtering, sorting, dedup and pagination are all pushed into SQL via squirrel, the
FTS lives in a separate GIN-indexed 1:1 table, and pagination is keyset (no `OFFSET` scan) on every
UI-facing endpoint. Result-set assembly is linear in page size with pre-sized slices. There is **no**
in-Go faceting, no in-Go re-sort, no in-Go dedup, no N+1 over child rows in the list path, and the
DSL post-filter regex pass operates over a bounded `limit+1` window, not the corpus.

The findings below are genuine but mostly MINOR. The one that matters under the stated ~250k-CVE
realistic load is the **missing composite keyset index** backing `(date_modified_canonical, cve_id)`
pagination — every UI search page and saved-search page relies on it, and the single-column index
forces a heap-sort/extra-row-scan on the tiebreak that grows with how deep a timestamp's CVE cluster
is. The corpus has large bulk-import bursts that share a timestamp, so the cluster is not provably
small.

---

### MAJOR — Keyset pagination lacks a composite index on `(date_modified_canonical DESC, cve_id DESC)`; tiebreak forces sort/extra scan that grows with same-timestamp clusters
**Location:** `migrations/000002_create_cve_core.up.sql:45-46` (only `cves (date_modified_canonical DESC)` exists) vs the keyset predicate/order in `internal/store/cve.go:197-203` (`SearchCVEs`) and `internal/store/dsl_executor.go:147-156` (`ExecuteDSLQuery`).
**Problem:** Both hot list/search paths order by `date_modified_canonical DESC, cve_id DESC` and page
with the row comparison `(date_modified_canonical, cve_id) < (?, ?)`. The only supporting index is
single-column on `date_modified_canonical`. Postgres can walk that index for the leading column, but
`cve_id` is not in the index, so (a) the composite `<` predicate cannot be fully pushed as an index
range — within rows sharing a `date_modified_canonical` value the planner must fetch and re-filter/
re-sort on `cve_id` from the heap, and (b) the `DESC, DESC` tiebreak is not satisfiable as a pure
ordered index walk. For pages landing inside a large same-timestamp cluster this degrades from
"read N index entries" toward "scan + sort the whole cluster" per page. Bulk CVE imports
(`import-bulk`) and feed batch-merges stamp many CVEs with near-identical `date_modified_canonical`,
so the cluster size is not provably bounded — exactly the case keyset pagination is supposed to make
O(page), not O(cluster).
**Impact:** Reached on **every** CVE list/search request and every saved-search/NL-search execution
(the two highest-frequency read endpoints in the slice). Per-page cost: best case unchanged; worst
case an extra heap fetch + sort proportional to the same-timestamp cluster depth, repeated per page
during deep pagination. Aggregate cost is high because frequency is high and the corpus is large.
**Confidence:** Strong-static (index DDL and query shape are both in-repo and unambiguous; the
planner consequence of a missing trailing sort column on a keyset predicate is standard).
**Effort:** Localized — add one migration:
`CREATE INDEX CONCURRENTLY ... ON cves (date_modified_canonical DESC, cve_id DESC)`. No code change;
squirrel already emits the matching `ORDER BY`/`WHERE`. (The existing single-column index can be
dropped afterward since the composite is a strict superset for these queries.)
**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` the search query on a seeded corpus with a
deliberately large same-timestamp cluster, before/after the composite index — expect the post-index
plan to drop the `Sort` node and show an index-only range scan, and `rows removed by filter` on the
keyset predicate to fall to ~0. Correctness guard: existing keyset-pagination tests in the store/api
suites pin row order and next-cursor stability across pages; they must stay green (ordering is
unchanged, only the access path changes).

---

### MINOR — Ecosystem/package and EPSS/CVSS range filters in `SearchCVEs` are not index-supported, so any filtered search degrades to a corpus scan
**Location:** `internal/store/cve.go:141-176` (CVSS `COALESCE(...)` range, ecosystem `EXISTS` subquery, package filter) and `:186-192` (EPSS `COALESCE(...)` range); supporting indexes in `migrations/000002_create_cve_core.up.sql:36-58`.
**Problem:** Several filter predicates cannot use an index as written:
- `COALESCE(cves.cvss_v4_score, cves.cvss_v3_score) >= ?` and `COALESCE(cves.epss_score, -1) >= ?`
  are expressions over columns with no matching expression index, so they are filter-only.
- The ecosystem/package `EXISTS (SELECT 1 FROM cve_affected_packages p WHERE p.cve_id = cves.cve_id
  AND p.ecosystem = ?)` correlates on `cve_id`; `cve_affected_packages` is indexed on `(cve_id)`
  (`:165-166`) but **not** on `(ecosystem, package_name)`, so resolving "all CVEs in ecosystem npm"
  must scan `cve_affected_packages` by ecosystem with no index.
When a user applies only these filters (no `q=` FTS join, no severity/KEV equality that hits an
index), the planner has no selective access path and falls back to a sequential scan of `cves`
(250k rows) and/or `cve_affected_packages`, bounded only by `LIMIT`. With a restrictive filter the
`LIMIT` may force scanning a large fraction of the corpus before filling a page.
**Impact:** Reached on filtered-without-FTS searches (a normal UI pattern: "show me all critical npm
CVEs"). Frequency moderate; per-occurrence cost up to O(corpus) when the filter is selective and the
matching rows are sparse near the cursor. Lower than the keyset finding because severity/KEV/exploit
equality filters (the common case) do have single-column indexes that bound the scan.
**Confidence:** Heuristic — depends on which filter combination a request uses and the planner's
choice; the absence of the supporting indexes is strong-static, the runtime impact is workload-shaped.
**Effort:** Contained — candidate indexes: `cve_affected_packages (ecosystem, package_name, cve_id)`
for the EXISTS lookup; optionally an expression index on
`COALESCE(cvss_v4_score, cvss_v3_score)` and on `epss_score` if range-only searches prove common.
Decide per measured query mix rather than indexing speculatively (YAGNI).
**Verification plan:** `EXPLAIN ANALYZE` representative filtered searches (ecosystem-only;
EPSS-range-only) on a seeded corpus; confirm seq-scan → index path after adding the ecosystem index.
Correctness guard: search filter tests pin the returned set for each filter combination.

---

### MINOR — `cveColumns` SELECT pulls every column (incl. `material_hash`, vector text) for list views that use a subset; over-fetch on the hot path
**Location:** `internal/store/dsl_executor.go:25-47` (`cveColumns`, 21 columns) consumed by `SearchCVEs` (`cve.go:126`) and `ExecuteDSLQuery` (`dsl_executor.go:127`); list response only needs the `CVEItem` subset (`internal/api/cves.go:64-79`).
**Problem:** Both list/search store methods `SELECT` all 21 CVE columns and `scanCVERow`
(`dsl_executor.go:51-79`) scans all of them into `generated.CVE`, but the list response `CVEItem`
discards `material_hash`, `date_modified_source_max`, `cvss_v*_source`, `cvss_v*_vector`,
`date_epss_updated`. `material_hash` and the CVSS vector strings are the widest text columns. Per
page this is wasted bytes off the wire, extra `pq.Array` allocation for `cwe_ids`, and extra scan
work — multiplied by page size (≤100) on every list/search request.
**Impact:** Reached on every list/search/saved-search page. Per-row constant-factor over-fetch
(several unused text columns + one unused array scan) × page size. Aggregate is a steady tax on the
busiest endpoints, but it is a constant factor, not a complexity change — hence MINOR.
**Confidence:** Strong-static (column list and consuming struct are both in-repo).
**Effort:** Contained — would require a list-specific column set + scan struct, or accepting the
shared `cveColumns`/`scanCVERow` for detail reuse. The shared slice is deliberately synchronized with
`scanCVERow` and `GetCVEDetail`, so splitting adds a parallel scan path to maintain; weigh against the
constant-factor gain. Reasonable to defer unless a profile flags row width.
**Verification plan:** Compare bytes-fetched / scan allocs for a 100-row page with the full vs.
trimmed column set (`go test -benchmem` around `scanCVERow`, or `EXPLAIN (ANALYZE, BUFFERS)` width).
Correctness guard: list-response tests assert `CVEItem` field values are unchanged.

---

### MINOR — `ListSavedSearches` orders by `updated_at DESC` with no index and no keyset; full sort per call (bounded by ≤200 rows/org)
**Location:** `internal/store/queries/saved_searches.sql:14-25` (`ORDER BY updated_at DESC LIMIT 200`), handler `internal/api/saved_searches.go:166-182`.
**Problem:** The saved-search list sorts the org's rows by `updated_at DESC` with no supporting index
and no cursor — it fetches up to 200 and sorts them in the DB each call. This is the only list
endpoint in the slice that is **not** keyset-paginated and has no ORDER BY index.
**Impact:** Bounded: `LIMIT 200` and saved searches per org are few. The sort is over a small,
provably-bounded n, so per the calibration guidance this is at the edge of "not a finding." Listed
only because it is the lone non-keyset list path in an otherwise consistent slice, and an index on
`(org_id, updated_at DESC)` would make it index-ordered for free if org saved-search counts ever grow.
**Confidence:** Strong-static (query + handler limit are in-repo).
**Effort:** Localized (one index) — but YAGNI applies; defer unless saved-search counts per org grow.
**Verification plan:** None warranted at current bounds; revisit if the 200 cap is raised or removed.

---

## What I examined and found clean

- **Faceting:** not implemented (only a stale comment in `cves.go:35`). No in-Go corpus scan to
  aggregate facets — the classic "build facets in Go" footgun is absent. Good.
- **Total-count-per-page:** none. No endpoint runs a separate `COUNT(*)` full scan alongside the
  page query; pagination uses the `limit+1` extra-row trick (`cves.go:339,377`;
  `dsl_executor.go:156,191-215`; all `*Handler` list paths). Avoids the common keyset+count anti-pattern.
- **DSL post-filter regex pass** (`dsl_executor.go:200-211`, `postfilter.go`): operates over the
  already-`LIMIT limit+1` SQL result window, not the corpus, and regexes are pre-compiled at compile
  time (`PostFilter.Pattern.MatchString`). Bounded n, no per-row compile. Correct.
- **Watchlist EXISTS subquery** (`compiler.go:114-131`): a single correlated EXISTS over
  `watchlist_items`, not N clauses per item. No accidental quadratic in rule compilation.
- **Result assembly:** all list handlers pre-size output slices (`make([]T, 0, len(rows))` /
  `make([]T, len(rows))`) and map 1:1 — linear, no nested loops joining CVEs to child rows in Go.
- **Watchlist list** (`watchlist.go:107-151`): the `LeftJoin ... GROUP BY ... COUNT(wi.id)` computes
  per-watchlist item counts in SQL (not an N+1 count-per-row in Go), keyset-paginated, `LIMIT 20`.
- **`GetCVEDetail`** (`cve.go:49-73`): 4 sequential single-key queries (cve + 3 child tables), each
  index-backed on `cve_id`. Bounded per CVE; not a list path. Sequential rather than batched but the
  per-call count is fixed at 4 — concurrency, not algorithmic, lane.
- **`alert_events` list** (`alert_rule.go:335-391`): keyset on `(first_fired_at, id)` with indexes on
  `org_id`, `rule_id`, `cve_id`, `first_fired_at`; filters all index-supported. Clean.
- **Cursor encode/decode**, `parseWatchlistUUIDs` dedup (`alert_rules.go:150-164`, uses a `map` set):
  appropriate containers, O(n).

---

## Suspected Bugs (for follow-up)

- `internal/store/cve.go:188-191` — EPSS range uses `COALESCE(cves.epss_score, -1) >= ?` for the min
  bound and `COALESCE(cves.epss_score, 2) <= ?` for the max bound. This means a CVE with **NULL** EPSS
  is *included* by an `epss_min` filter only if `-1 >= min` (i.e. never, for any valid min ≥ 0) and
  included by an `epss_max` filter only if `2 <= max` (i.e. never, for any valid max ≤ 1). The
  asymmetric sentinels make NULL-EPSS rows always fail a present min filter and always fail a present
  max filter — which is plausibly the intended "rows with no EPSS shouldn't match an EPSS range," but
  the code comment claims COALESCE is there so "NULLs don't silently drop rows," which is the
  opposite of the actual effect. Worth confirming the intent matches the behavior. (Recorded, not
  chased — not a performance issue.)
```
