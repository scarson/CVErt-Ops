# Execution Cost Map — S4 Search, CVE read & watchlist
> Architectural awareness, NOT an optimization to-do list. Descriptive map of where a
> search/read request spends time, reasoned from code structure (query count, result-set
> size, join fan-out, serialization size) — no fabricated numbers, no runtime profiling.

Scope read: `internal/api/{cves,saved_searches,alert_events,watchlists,alert_rules}.go`,
`internal/store/{cve,dsl_executor,saved_search,watchlist,alert_rule}.go`,
`internal/store/queries/{cves,watchlist}.sql`, `internal/store/store.go` (tx helpers),
`internal/api/contract.go` (serialization helpers).

Hot endpoints in this slice: `GET /cves` (search), `GET /cves/{id}` (detail),
`GET /cves/{id}/sources`, `POST .../saved-searches/{id}/execute`, `GET .../alert-events`,
`GET .../watchlists`, `GET .../watchlists/{id}`, `GET .../watchlists/{id}/items`.

---

### Likely time-concentration regions

- **FTS `@@` GIN index scan on `cve_search_index` (GET /cves with `q`, saved-search execute)**
  — basis: when `q` is set, the query JOINs `cve_search_index` and filters
  `fts_document @@ websearch_to_tsquery('english', q)` (`cve.go:129-133`,
  `dsl_executor.go` via compiled Joins). On a ~250k+ corpus the GIN posting-list walk +
  tsquery match is the dominant unit cost of a text search, and it runs once per request on
  the interactive path. Selectivity-dependent: broad/common terms touch large posting lists;
  the subsequent keyset `ORDER BY date_modified_canonical DESC` may force a sort or
  bitmap-heap re-fetch of the matched candidate set rather than a cheap index-ordered scan.
  — confidence: High (structure certain; magnitude selectivity-dependent)
  — also flagged by data-access (index strategy / GIN + ORDER BY interaction)

- **Keyset-paginated corpus scan + composite sort (GET /cves, saved-search execute, every page)**
  — basis: both `SearchCVEs` (`cve.go:124-229`) and `ExecuteDSLQuery` (`dsl_executor.go:121`)
  order by `(date_modified_canonical DESC, cve_id DESC)` with a row-comparison cursor and
  `LIMIT n+1`. Per request the planner must produce the top-N in sort order after applying
  all filters. Without a matching composite/descending index the dominant cost is the sort of
  the filtered candidate set; with one it is an index range scan. This is the single most
  frequent query in the slice (default page = every search/browse action).
  — confidence: High
  — also flagged by data-access (composite index for keyset order)

- **Per-request `BEGIN` + `SET LOCAL app.org_id` round-trip on every org-scoped read**
  — basis: org-scoped reads run inside `withOrgRawTx`/`withOrgTx` (`store.go:101-130`), which
  issues `BEGIN`, a separate `SET LOCAL app.org_id = …` statement, the query, then `COMMIT`.
  That is a minimum of ~3 statements/round-trips per handler even for a single-row fetch
  (`GetWatchlist`, `GetSavedSearch`, `ListWatchlists`, `ListAlertEvents`, watchlist items).
  Fixed per-request overhead multiplied across the interactive request rate; constant-factor,
  not big-O, but it lands on every org-scoped read in the slice. (Note: `GET /cves*` is global
  and does NOT pay this — it queries `s.db`/`s.q` directly.)
  — confidence: High
  — also flagged by data-access (round-trips per op), concurrency (tx/connection hold time)

- **Dynamic filter predicates that can't use a plain index: CVSS COALESCE, EPSS COALESCE,
  CWE `= ANY`, ecosystem/package EXISTS subquery (GET /cves with those filters)**
  — basis: `cve.go:141-176,187-192`. `COALESCE(cvss_v4_score, cvss_v3_score) >= ?` and
  `COALESCE(epss_score, -1) >= ?` are expression predicates that won't hit a column index
  unless a matching expression index exists; `? = ANY(cves.cwe_ids)` needs a GIN on the array;
  the ecosystem/package filter is a correlated `EXISTS` against `cve_affected_packages` (one
  semijoin probe per candidate CVE). Cost concentrates only when these filters are supplied,
  and scales with the pre-filter candidate count. Per-request frequency = whenever a user
  narrows by score/CWE/package.
  — confidence: Medium (depends on which expression/GIN indexes exist — not visible in this slice)
  — also flagged by data-access (expression/array/EXISTS index coverage)

- **CVE detail = 4 sequential round-trips, no concurrency (GET /cves/{id})**
  — basis: `GetCVEDetail` (`cve.go:49-73`) issues GetCVE, then GetCVEReferences,
  GetCVEAffectedPackages, GetCVEAffectedCPEs strictly in sequence; each is its own
  `s.q.*` round-trip. Latency is the sum of four serial DB hits rather than one batched/joined
  fetch or concurrent fan-out. Each child query is itself a cheap indexed lookup by `cve_id`,
  so the cost is round-trip latency × 4, not row volume — matters most under network/DB RTT.
  — confidence: High
  — also flagged by data-access (N sequential queries), concurrency (serial where parallel possible)

- **Row → DTO conversion + JSON serialization per page (all list endpoints)**
  — basis: every list handler loops results building DTOs (`cveToItem` at `cves.go:161`,
  `savedSearchToEntry`, `watchlistToEntry`, `alertEventEntry`) then `json.NewEncoder(w).Encode`
  (`contract.go:18-24`). Per-row work: several `time.Format(RFC3339)` calls (string alloc each),
  pointer-boxing of nullable fields, and array copies. Frequency = result_count per page ×
  request rate. `cveToItem` is the heaviest (≈10 nullable checks + 2 time formats + CWE slice).
  Bounded by page size (≤100 for /cves, 200 saved-searches, 100 alert-events), so per-request
  cost is bounded and modest — a constant-factor region, not a scaling cliff. Saved-search
  execute and `GET /cves` carry the largest per-row DTO.
  — confidence: High
  — also flagged by memory (per-row allocs: time.Format strings, pointer boxing)

- **GET /cves/{id}/sources — JSON passthrough of `normalized_json` raw payloads**
  — basis: `getCVESourcesHandler` (`cves.go:497`) returns one `normalized_json`
  (`json.RawMessage`) per source row. A CVE merged from many feeds (NVD/MITRE/GHSA/OSV/KEV/
  MSRC/RedHat) returns several large raw JSON blobs; response size and the encoder's copy of
  each `RawMessage` dominate cost here, not query time. Cost scales with payload size × source
  count, independent of corpus size. Lower frequency than list/detail (cross-source compare view).
  — confidence: Medium (depends on stored payload sizes)
  — also flagged by memory (large RawMessage buffering), payload (response size)

- **Saved-search execute: parse + validate + compile DSL on every invocation**
  — basis: `executeSavedSearchHandler` (`saved_searches.go:427-446`) runs `dsl.Parse` →
  `dsl.Validate` → `dsl.Compile` on each POST before touching the DB; the compiled rule is not
  cached across executions. CPU-bound JSON parse + AST build per request. Small relative to the
  DB query for typical rules, but it is pure per-request overhead on a repeatable endpoint
  (same saved search re-run for pagination pays the full compile each page).
  — confidence: Medium
  — map-only

- **Saved-search execute post-filters: in-process regex over fetched page (when regex conditions present)**
  — basis: `ExecuteDSLQuery` applies `dsl.ApplyPostFilters` in Go after SQL fetch
  (`dsl_executor.go:200-211`), re-slicing/copying the result set (`make` + element copy twice).
  Bounded by page size, so modest; concentrates only for rules with regex conditions, and adds
  one extra full-slice copy of the page even when no post-filter removes rows.
  — confidence: Medium
  — also flagged by memory (double slice copy of page), algorithmic (regex per row)

- **ListWatchlists: LEFT JOIN + GROUP BY to compute per-watchlist item_count (GET /watchlists)**
  — basis: `store/watchlist.go:107-151` joins `watchlist_items` and `COUNT(wi.id)` GROUP BY
  watchlist per page (limit 20). Aggregation fan-out scales with items-per-watchlist; bounded
  by page size and per-org data volume (small relative to global corpus). The count is computed
  on every list page rather than maintained as a denormalized counter.
  — confidence: Medium
  — also flagged by data-access (aggregate-on-read vs maintained counter)

- **Watchlist GET / PATCH: multiple queries per request**
  — basis: `GetWatchlist` runs GetWatchlist + CountWatchlistItems inside one tx
  (`watchlist.go:84-102`) = 2 queries + SET LOCAL. `updateWatchlistHandler`
  (`watchlists.go:316-412`) does GetWatchlist (→2 queries) → UpdateWatchlist → GetWatchlist
  again to refresh item_count (→2 more), i.e. ~5 queries across 3 transactions for one PATCH.
  Low frequency (mutation), so aggregate impact is small, but it is the densest query-count
  region in the watchlist sub-slice.
  — confidence: High
  — also flagged by data-access (query count per op)

---

### Notes for architecture

- **No facet/aggregation endpoint exists in this slice.** Despite the `cves.go` file header
  mentioning "faceted search," there is no facet count query and no `COUNT(*)` over the corpus
  on the search path. The prompt's "facet aggregation over the corpus" cost region is therefore
  NOT present today — search uses pure keyset pagination with no total-count query. If faceting
  is added later, count/aggregation over the 250k+ corpus per request would become a top-tier
  cost region; flagging now as the most likely future hot spot.
- **Search has no `OFFSET` scan and no total-count query** — keyset `(sort_col, cve_id)` only.
  This avoids the classic deep-pagination cost; the only legacy `LIMIT/OFFSET` path is the
  static `ListCVEs` (`cves.sql:186-192`), which the API layer does not use (squirrel handles
  the filtered path). Good baseline; cost stays bounded as users page deep.
- **The two dominant, always-present costs are the FTS GIN scan (text searches) and the
  filtered keyset sort (all searches).** Everything else in the slice is bounded by page size
  (≤100–200 rows) and is constant-factor per-request work — real but not a scaling cliff.
- **`GET /cves*` is global / RLS-free** and skips the `withOrgTx` `SET LOCAL` round-trip, so the
  highest-frequency endpoint pays the least per-request fixed overhead — a sensible split. The
  org-scoped read endpoints (watchlists, saved searches, alert events) each pay the 3-statement
  transaction floor; that floor dominates their cost more than their (small, indexed) queries do.
- **CVE detail's 4 serial round-trips** are the clearest latency-vs-structure region: each child
  query is cheap, but they are summed sequentially. A joined/batched fetch or concurrent fan-out
  would convert sum-of-RTT to max-of-RTT. Recorded as a map observation, not a directive.

### Suspected Bugs (for follow-up)
None observed in the read paths examined.
