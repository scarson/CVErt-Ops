# S4 — Search, CVE read & watchlist — data-access & I/O lane

ABOUTME: Performance audit of the hot UI read path (CVE search/detail/sources, saved searches, watchlists, alert events) for data-access and I/O problems.
ABOUTME: Focus on index alignment with keyset pagination, FTS query shape, N+1 child fetches, over-fetch, and per-request query counts.

Scope read: `internal/api/cves.go`, `saved_searches.go`, `alert_events.go`, `watchlists.go`, `alert_rules.go`;
`internal/store/cve.go`, `dsl_executor.go`, `saved_search.go`, `watchlist.go`, `alert_rule.go (ListAlertEvents)`;
`internal/store/queries/cves.sql`, `watchlist.sql`; DDL in `migrations/000002`, `000014`, `000016`, `000023`.

No runtime profiling available (no Docker). Confidence is `Strong-static` where code/DDL structure makes the conclusion certain, `Heuristic` where it depends on data distribution/cardinality I cannot measure.

---

### [CRITICAL] CVE list keyset pagination has no composite index — every search page beyond page 1 sorts/scans the corpus

**Location:** `internal/store/cve.go:194-203` (`SearchCVEs` WHERE/ORDER BY); `internal/store/dsl_executor.go:142-156` (`ExecuteDSLQuery`); index `cves_date_modified_canonical_idx` at `migrations/000002_create_cve_core.up.sql:45-46`.

**Problem:** The hot list query orders by `(date_modified_canonical DESC, cve_id DESC)` and seeks with the row-comparison cursor
`(cves.date_modified_canonical, cves.cve_id) < (?, ?)`. The only supporting index is single-column `cves (date_modified_canonical DESC)`. A single-column index cannot serve the composite tiebreak: Postgres can use it to seek to the cursor's `date_modified_canonical`, but `cve_id` is not in the index, so within any group of rows sharing the same timestamp (and at the cursor boundary) it must heap-fetch and re-filter/re-sort to honor the `cve_id` tiebreak and the strict `<` row comparison. More importantly, the row-comparison predicate `(a,b) < (c,d)` is only an index-friendly seek when **both** `a` and `b` are leading index columns in matching sort order; with `cve_id` absent the planner degrades to a scan of the `date_modified_canonical` range plus a sort, or (depending on stats) a full Seq Scan + Sort of the ~250k-row corpus. The CLAUDE.md hot-path contract explicitly requires "composite-cursor WHERE + ORDER BY match a real composite index" — that index does not exist.

This is the default, unfiltered, every-user CVE browse path (`GET /cves`), and it is also the shape used by saved-search execution (`ExecuteDSLQuery`) and the alert activation candidate scan. The cost is paid on **every page load**.

**Impact:** Reachability: maximal (default list view, no filter needed to hit it). Frequency: every CVE-list page request and every saved-search execution. Per-occurrence: on a 250k-row corpus, a missing-seek keyset query is O(N log N) sort or O(N) scan-and-discard instead of an O(log N + limit) index range scan — the canonical "deep pagination scans the whole set" failure, except here it bites from page 1 because the tiebreak isn't covered. Buffers read scale with corpus size, not page size.

**Confidence:** Strong-static — the index DDL and the ORDER BY/WHERE column lists are both in scope and demonstrably mismatched on the second sort key.

**Effort:** Localized — add one migration:
`CREATE INDEX CONCURRENTLY cves_keyset_idx ON cves (date_modified_canonical DESC, cve_id DESC);`
No code change needed (the query already emits the correct shape). The existing single-column index can later be dropped since the composite serves the same date-range predicates as a prefix.

**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` the list query with a non-empty cursor before/after the new index; expect the plan to change from `Seq Scan + Sort` (or `Index Scan` on the single-col index with `Rows Removed by Filter` and a separate Sort) to a clean `Index Scan Backward using cves_keyset_idx` with `rows ≈ limit` and buffer reads independent of corpus size. Correctness guard: existing `SearchCVEs`/`ExecuteDSLQuery` pagination tests must still return identical row order and cursor continuity across page boundaries (the index changes the plan, not the result set).

---

### [MAJOR] CVSS-range filter is non-sargable: `COALESCE(cvss_v4_score, cvss_v3_score)` defeats any index, forcing a full scan

**Location:** `internal/store/cve.go:141-147` (CVSS min/max); also EPSS at `:186-192` (`COALESCE(epss_score,-1)` / `COALESCE(...,2)`).

**Problem:** The CVSS filter wraps the indexed-candidate columns in `COALESCE(cves.cvss_v4_score, cves.cvss_v3_score) >= ?`. Wrapping columns in a function/expression makes the predicate non-sargable — Postgres cannot use a plain B-tree on either `cvss_v4_score` or `cvss_v3_score` and must compute the COALESCE per row over the whole candidate set, then filter (`Rows Removed by Filter`). There is in fact **no index on either CVSS score column at all** (`migrations/000002` indexes severity, KEV, exploit, dates, GIN cwe/trgm — none on `cvss_v3_score`/`cvss_v4_score`), so even a sargable rewrite would need a new expression index. The EPSS range has the same COALESCE-sentinel non-sargability and also lacks any `epss_score` index. When a CVSS or EPSS range is the *only* selective filter, the query scans the corpus.

**Impact:** Reachability: high — "CVSS ≥ 7" / "EPSS ≥ 0.5" are primary triage filters in a vuln-intel UI. Frequency: per filtered search. Per-occurrence: full candidate scan + per-row COALESCE eval instead of an index range seek; O(N) over ~250k rows when the range filter is the driving predicate. The severity filter (`cves_severity_idx`) partially mitigates when combined, but CVSS-only and EPSS-only searches have no usable index.

**Confidence:** Strong-static for non-sargability and the absence of CVSS/EPSS indexes (DDL in scope). Heuristic on aggregate cost — depends how often users filter by score alone vs. alongside an indexed predicate.

**Effort:** Contained. Two options: (a) add expression indexes `CREATE INDEX ... ON cves ((COALESCE(cvss_v4_score, cvss_v3_score)))` and `... ON cves (epss_score)` to make the existing predicates sargable (the EPSS COALESCE-with-sentinel still won't use a plain `epss_score` index — rewrite to `(epss_score >= ? OR (epss_score IS NULL AND ? <= 0))`-style sargable form, or a partial index); or (b) precompute a `cvss_score` canonical column populated by the merge pipeline and index it. Option (a) is the smaller change.

**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` a `?cvss_min=7` query and a `?epss_min=0.5` query before/after. Expect `Seq Scan` + high `Rows Removed by Filter` to become an index range scan with the expression index. Correctness guard: range-filter tests (including the NULL-row-retention behavior the COALESCE sentinel was added for — pitfall §pagination) must keep returning rows whose score column is NULL only where the sentinel intends.

---

### [MAJOR] `ListWatchlists` left-joins all items and `GROUP BY`/`COUNT`s on every page load — fan-out + aggregate that an index can't remove

**Location:** `internal/store/watchlist.go:107-151` (`ListWatchlists`).

**Problem:** The watchlist list query does `LEFT JOIN watchlist_items wi ON wi.watchlist_id = w.id AND wi.deleted_at IS NULL ... GROUP BY w.id` purely to compute `COUNT(wi.id) AS item_count` per watchlist. This joins one-to-many and then aggregates — for every page of 20 watchlists it reads and hashes **all live items of all 20 watchlists** and runs a HashAggregate. `watchlist_items` has an index on `watchlist_id` (`watchlist_items_watchlist_id_idx`) so the join lookups are indexed, but the per-page aggregate still materializes and counts every item row, and the `GROUP BY w.id` + `ORDER BY w.created_at DESC, w.id DESC` may force a sort that the count aggregation can't stream from `watchlists_created_at_idx` (single-column `created_at`, not the composite keyset — same class of mismatch as the CVE finding, see Suspected Bugs note).

**Impact:** Reachability: high (watchlist index page, viewer+). Frequency: every list load. Per-occurrence: O(items across the page's watchlists) extra row processing per page; for orgs with large watchlists this is the dominant cost of a list that should be ~20 cheap row reads. Bounded by page size × items-per-watchlist, so not unbounded, but it scales with item count rather than page size.

**Confidence:** Strong-static on the query shape; Heuristic on magnitude (depends on items-per-watchlist, which I can't measure — small for most orgs, large for power users).

**Effort:** Contained. Replace the join-and-aggregate with a correlated scalar subquery `(SELECT count(*) FROM watchlist_items wi WHERE wi.watchlist_id = w.id AND wi.deleted_at IS NULL) AS item_count` (one indexed count per row, no fan-out, no GROUP BY, lets the ORDER BY stream from the keyset index), or a `LATERAL` count. Even better for a hot list: drop the live count from the list response and show it only on detail (`GetWatchlist` already counts separately), or maintain a denormalized counter.

**Verification plan:** `EXPLAIN (ANALYZE)` before/after; expect `HashAggregate` over a wide join to become per-row index-only counts and the GROUP BY/Sort to disappear. Correctness guard: `ListWatchlists` tests asserting `item_count` values across watchlists with mixed deleted/live items.

---

### [MINOR] FTS search and severity filter cannot combine in one index scan — FTS uses GIN, all scalar filters post-filter the matched set

**Location:** `internal/store/cve.go:128-184` (FTS JOIN + scalar WHEREs).

**Problem:** When `q` is present the query joins `cve_search_index` and applies `fts_document @@ websearch_to_tsquery(...)`, which correctly uses the GIN index `cve_search_index_fts_idx` (good — no ILIKE fallback). But all the scalar filters (severity, CVSS, KEV, dates, ecosystem EXISTS) are then applied as post-filters on the FTS match set, and the result is ordered by `date_modified_canonical DESC` — which the GIN index cannot provide. So a broad FTS term (e.g. "linux") that matches tens of thousands of rows must materialize the whole match set, apply scalar filters, then **sort the entire filtered set** by date before LIMIT. GIN gives no ordering, so the date sort is unavoidable for FTS queries; this is inherent to combining FTS with a date-ordered keyset and is a known trade-off, not a defect — but a very broad query term has no upper bound on the match set it sorts before applying LIMIT.

**Impact:** Reachability: moderate (text search with a common term). Frequency: per FTS search. Per-occurrence: sort of the full FTS match set (could be 10k–100k rows for a broad term) per page. Narrow/selective terms are cheap. There is no candidate cap on FTS match size in the search path (unlike the regex 5,000-row cap in alert eval), so a pathological single-word query sorts a large fraction of the corpus.

**Confidence:** Heuristic — magnitude depends entirely on term selectivity, which varies per query.

**Effort:** Contained. Options: cap FTS-driven searches by also requiring a date or severity predicate, or accept the sort but bound it (e.g. add `ts_rank`-based ordering with a match cap, or push a `LIMIT` on a CTE of the top-N most-recent matches). Lowest-effort mitigation: document the bound and rely on selective terms; only act if profiling shows broad-term searches are a real load.

**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` a single common-word `?q=` with no other filter; observe `Sort` rows ≈ match-set size. If broad terms are reachable in the UI, add a cap and re-measure. Correctness guard: FTS relevance/order tests.

---

### [MINOR] CVE detail issues 4 sequential round-trips per request where the child fetches could run as one round-trip

**Location:** `internal/store/cve.go:49-73` (`GetCVEDetail`); handler `internal/api/cves.go:411-477`.

**Problem:** `GetCVEDetail` does four sequential `QueryContext`/`QueryRow` calls — `GetCVE`, `GetCVEReferences`, `GetCVEAffectedPackages`, `GetCVEAffectedCPEs` — each its own DB round-trip on `s.q` (the shared pool), serialized. This is not an N+1 (it's a fixed 4, not per-row), and each child query is indexed on `cve_id`. But for a hot detail endpoint, four serial round-trips pay 4× network latency per request when the three child fetches are independent and could be issued as a single `pgx.Batch` (one round-trip) or run concurrently. The `/cves/{id}/sources` handler adds a 5th independent round-trip (`GetCVE` existence check then `GetCVESources` — `internal/api/cves.go:503-511`), where the existence check could be folded.

**Impact:** Reachability: high (every CVE detail view). Frequency: per detail load. Per-occurrence: 3 avoidable serial RTTs (each = one network latency unit). Modest per request but on the single most-viewed detail endpoint. Not a scan/index problem — pure round-trip latency.

**Confidence:** Strong-static on the serial round-trip structure.

**Effort:** Contained — batching requires either `pgx.Batch` (the project uses pgx under `database/sql`, so a native-pgx path or an `errgroup` of the three independent child queries) or accepting the current shape. The three child queries are independent and have no ordering dependency, so an `errgroup.WithContext` fan-out is a safe, localized win without touching SQL. Weigh against added concurrency complexity on a path whose absolute latency is already small.

**Verification plan:** Measure RTT count (4→2) via query logging; or benchmark detail-endpoint p50 latency before/after fan-out against a representative-latency DB. Correctness guard: `GetCVEDetail` tests asserting all child tables populate correctly, including the empty-child and not-found cases.

---

## Notes on items the slice named that are NOT findings

- **Facet/count queries doing full scans per request:** There is **no facet or count-over-corpus query in the current code**. `registerCVERoutes` (`internal/api/cves.go:27-59`) registers only list/detail/sources; the list path uses fetch-Limit+1 to detect next page (`internal/api/cves.go:339,377`) — it does **not** issue a separate `COUNT(*)` over the filtered corpus per page. The "facets aggregate over the corpus" hot-path fact describes a PLAN feature not yet implemented. No finding; flagged so a future facet implementation gets its own audit.
- **`ListCVEs` OFFSET pagination (`cves.sql:186-192`)** uses `LIMIT $1 OFFSET $2` (deep-offset antipattern) but is **not on the hot read path** — the handler calls `SearchCVEs` (keyset) exclusively. `ListCVEs` appears unused by the API read path. Not a finding for this slice; noted for dead-code/retention review.
- **Watchlist-items and alert-events list pagination** (`watchlist.go:227-271`, `alert_rule.go:335-391`) use proper keyset cursors and have supporting indexes (`watchlist_items_watchlist_id_idx`, `alert_events_first_fired_at_idx`, `alert_events_cve_id_idx`, `alert_events_rule_id_idx`). The `alert_events` keyset is `(first_fired_at DESC, id DESC)` against a single-column `first_fired_at` index — same prefix-only class as the CVE finding but far lower-cardinality table and bounded by 1-year retention, so MINOR at most; see Suspected Bugs.
- **Saved-search list** (`saved_search.go:111-130`) caps at ≤200 and is org+user indexed; fine.
- **Over-fetch:** `SearchCVEs`/`ExecuteDSLQuery` select the full 21-column `cveColumns` set (no `SELECT *` wildcard, no large JSONB — `normalized_json` is only fetched on the explicit `/sources` endpoint). `cwe_ids` is a small `text[]`. No material TOAST over-fetch on the list path. Not a finding.

---

## Suspected Bugs (for follow-up)

- **`alert_events` keyset index is single-column** (`migrations/000016:90-91` indexes `(first_fired_at)`) while the query orders/seeks on `(first_fired_at DESC, id DESC)` (`alert_rule.go:345,361`). Same prefix-only mismatch as the CRITICAL CVE finding but on a smaller, retention-bounded table. Performance-adjacent, lower impact; consider a composite `(first_fired_at DESC, id DESC)` if this list grows hot.
- **`watchlists` keyset index is single-column** (`migrations/000014:77-78` indexes `(created_at)`) while `ListWatchlists` orders on `(created_at DESC, id DESC)` (`watchlist.go:117,121`). Contributes to the MAJOR `ListWatchlists` finding's inability to stream the ORDER BY; a composite `(created_at DESC, id DESC)` would help once the GROUP BY is removed.
</content>
</invoke>
