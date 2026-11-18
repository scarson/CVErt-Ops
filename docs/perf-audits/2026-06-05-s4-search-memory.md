# S4 — Search, CVE read & watchlist — memory & allocation lane

ABOUTME: Performance audit (memory/allocation lane) of the S4 hot read-path slice.
ABOUTME: Covers CVE search/detail/sources, saved-search execute, watchlists, alert events/rules read paths.

Auditor lane: **memory & allocation**. No runtime profiling available — all findings are
static/heuristic, never `Measured`.

## Scope examined

- `internal/api/cves.go` (list/detail/sources handlers + DTO conversion)
- `internal/api/saved_searches.go`, `alert_events.go`, `watchlists.go`, `alert_rules.go`
- `internal/store/cve.go` (`SearchCVEs`, `GetCVEDetail`, `GetCVESources`), `dsl_executor.go`
- `internal/store/saved_search.go`, `watchlist.go`
- `internal/store/queries/cves.sql`, generated models, `internal/api/contract.go` (response writers)

A note on a non-finding from the slice brief: there is **no facet-aggregation endpoint** in the
code. "Faceted search" in the cves.go doc strings refers only to scalar WHERE filters
(severity/cwe/ecosystem/booleans), which are pushed into the SQL `WHERE` and never materialized as
Go-side aggregate maps. So "building large facet/aggregate maps in Go" is not reachable here.
`writeJSON`/`writeList` already stream via `json.NewEncoder(w).Encode` (contract.go:21), so the
classic whole-buffer `json.Marshal` footgun is avoided on the chi-handler endpoints.

---

## Findings

### [MAJOR] `GET /cves/{id}/sources` materializes and copies every source's full raw JSON with no cap on count or per-blob size
**Location:** `internal/api/cves.go:497-537` (`getCVESourcesHandler`), `internal/store/cve.go:84-86` (`GetCVESources`), `internal/store/queries/cves.sql:69-70` (`SELECT *`)
**Problem:** The query is `SELECT * FROM cve_sources WHERE cve_id = $1` with no `LIMIT`. Each row
carries `NormalizedJson json.RawMessage` — the *entire* per-source normalized upstream payload
(NVD, MITRE, GHSA, OSV, KEV, MSRC, Red Hat, EPSS, plus any vendor sources). For a heavily-merged
CVE these blobs are individually tens of KB (raw NVD CVE JSON with CPE match trees, full reference
lists, multiple CVSS metric objects). The handler then builds a *second* slice
`out := make([]CVESourceResponse, 0, len(srcs))` and copies each `RawMessage` across (cve.go:516-533).
Peak live memory = (all source blobs from the DB driver) + (the `[]CveSource` slice) + (the
`[]CVESourceResponse` slice, whose `RawMessage` fields alias the same backing arrays but the structs
themselves are re-allocated) — all resident before serialization begins.
**Impact:** Reachability: UI-facing read endpoint (CVE detail "sources" tab). Frequency: per CVE
detail view. Per-occurrence cost: response size and peak heap scale linearly with
(#sources × avg-blob-size), unbounded — a CVE with 8 sources × ~40 KB raw JSON is a ~320 KB
response fully resident in Go heap (DB buffers + driver decode + DTO slice) before the first byte.
No `LIMIT`, no size guard. Multiple concurrent detail-page loads multiply this.
**Confidence:** Strong-static (no cap in query or handler; `RawMessage` carries the full blob).
**Effort:** Localized — the copy loop is avoidable; a hard cap is one query change. (The
"copy into a second DTO slice" is the cheap part — the `RawMessage` aliases the same bytes — so the
real lever is bounding total bytes / source count, e.g. paginating sources or capping blob size.)
**Verification plan:** Allocation argument: live bytes = Σ blob_i with no upper bound; adding a
`LIMIT`/byte budget bounds it to a constant. Correctness guard: a test asserting all expected
source rows for a multi-source CVE are returned (golden corpus CVE) pins behavior; if a cap is
introduced, the test must assert the cap boundary and that the response stays well-formed.

### [MAJOR] CVE list/search/saved-search over-fetch and over-scan: 21 columns (incl. vectors, sources, material_hash) materialized per row but the list DTO uses ~14
**Location:** `internal/store/dsl_executor.go:25-79` (`cveColumns` + `scanCVERow`), used by `internal/store/cve.go:124-229` (`SearchCVEs`) and `internal/store/dsl_executor.go:121` (`ExecuteDSLQuery`); DTO at `internal/api/cves.go:161-197` (`cveToItem`)
**Problem:** Both the dynamic search (`SearchCVEs`) and saved-search execution (`ExecuteDSLQuery`)
select the full `cveColumns` list (21 columns) and scan into the full `generated.CVE` struct. The
list-view DTO `CVEItem` (cves.go:64-79) reads only `cve_id, status, date_published,
date_modified_canonical, date_first_seen, description_primary, severity, cvss_v3_score,
cvss_v4_score, cvss_score_diverges, cwe_ids, exploit_available, in_cisa_kev, epss_score`. The
fetched-but-discarded columns include two CVSS **vector** strings, three `*_source` strings,
`date_modified_source_max`, `date_epss_updated`, and `material_hash` — every one a `sql.NullString`
(heap string on scan). On a 250k+ corpus search returning a full page (limit up to 100 + 1), that is
~6 wasted string allocations per row plus the DB-side cost of reading those wide TOAST-able columns
(`cvss_v3_vector`/`cvss_v4_vector`/`description_primary` can detoast). The `description_primary`
itself *is* used so it must be fetched, but the vectors and hash are pure waste on the list path.
**Impact:** Reachability: the primary UI search endpoint and saved-search execute — the hottest read
path in the slice. Frequency: every paginated search/scroll. Per-occurrence cost: ~6 extra
`sql.NullString` scans/allocs × up to 101 rows ≈ ~600 avoidable string allocations/page, plus extra
DB read/transfer for vector columns. Constant-factor, but on the busiest endpoint × corpus scale.
**Confidence:** Strong-static (column list vs DTO field set is directly comparable).
**Effort:** Contained — `SearchCVEs`/`ExecuteDSLQuery` share `cveColumns`/`scanCVERow` with the
detail path (`GetCVEDetail` reuses `generated.CVE`), so splitting a narrow list-projection requires
a separate column set + scan target and touching both callers. The detail endpoint legitimately
needs vectors, so this is a projection split, not a global trim.
**Verification plan:** Allocation argument: dropping `cvss_v3_vector, cvss_v4_vector, cvss_v3_source,
cvss_v4_source, date_modified_source_max, date_epss_updated, material_hash` from the list projection
removes N_unused × page_size string scans. Correctness guard: existing `SearchCVEs` / list-handler
tests asserting the returned `CVEItem` JSON shape pin that no consumed field regresses; add a test
that the narrowed scan still fills every `CVEItem` field for a corpus row.

### [MINOR] DSL post-filter path re-materializes the entire result slice by value (large struct copy)
**Location:** `internal/store/dsl_executor.go:200-211`
**Problem:** When a saved search / NL query has regex post-filters, the executor first builds
`wrapped := make([]cvePostFilterTarget, len(results))` (one pointer-wrapper per row — cheap), then
after filtering does `results = make([]generated.CVE, len(filtered))` and copies each matched row
**by value** (`results[i] = *filtered[i].cve`). `generated.CVE` is a wide struct (~20 fields, many
`sql.NullString`/`NullFloat64`/`NullTime` + a `[]string`), so this is a full second materialization
of the surviving rows. Since `filtered` already holds pointers into the original `results` backing
array, the value-copy and re-allocation are avoidable — a `[]*generated.CVE` (or compacting in
place) would skip the copy.
**Impact:** Reachability: only saved searches / NL queries that contain regex conditions (post-filter
present). Frequency: per execution of such a query. Per-occurrence cost: one extra slice allocation
+ a by-value copy of every matched wide struct (≤ limit+1, so ≤101). Bounded small-n, hence MINOR,
but it is pure avoidable churn on a read path.
**Confidence:** Strong-static.
**Effort:** Localized — change the post-filter return handling to reuse pointers / compact in place;
the value copy at the end (`*filtered[i].cve`) is what forces the second allocation.
**Verification plan:** Allocation argument: eliminating the `make([]generated.CVE, …)` + value copy
removes one O(matched) allocation and the per-row struct copy. Correctness guard: the existing
`ExecuteDSLQuery` post-filter pagination tests (`dsl_executor_test.go`) pin that cursor/trim behavior
and result identity are unchanged.

### [MINOR] `cveToItem` / detail DTO take `generated.CVE` by value, copying the wide struct per row
**Location:** `internal/api/cves.go:161` (`func cveToItem(c generated.CVE)`), called at `cves.go:384` (`items[i] = cveToItem(r)`) and `saved_searches.go:457`
**Problem:** `cveToItem` accepts `generated.CVE` **by value**. The list handler iterates
`for i, r := range rows` (also a per-iteration value copy of the wide struct from the slice) and
passes `r` in, a second copy. `generated.CVE` is large (≈20 fields incl. several 16-byte
`sql.Null*` and a slice header), so each list row is copied twice before its fields are read. Taking
`*generated.CVE` (and ranging with an index) would avoid both copies.
**Impact:** Reachability: every list/search/saved-search page render. Frequency: per row per page.
Per-occurrence cost: two wide-struct copies per row × up to 100 rows/page. These are stack copies
(no heap alloc), so the cost is memory bandwidth, not GC pressure — hence MINOR, but it is on the
hottest endpoint.
**Confidence:** Strong-static.
**Effort:** Localized — change the signature to a pointer and range by index in the two callers.
**Verification plan:** Complexity argument: removes 2 × sizeof(CVE) copies per row. Correctness
guard: list-handler JSON-shape tests already cover output equivalence; a pointer receiver does not
change semantics (read-only conversion).

---

## Things checked and judged NOT findings

- **`writeJSON` / `writeList` / `writeProblem` (contract.go:18-105):** already stream via
  `json.NewEncoder(w).Encode` directly to the `ResponseWriter` — no whole-buffer `json.Marshal`,
  no intermediate `[]byte`. Correct per the serialization pack. Not a finding.
- **Watchlist list/items handlers (watchlists.go) + store (watchlist.go):** all reads are
  page-bounded (const limits 20/50, store `Limit(limit)`), scan row-by-row into pre-sized
  `make([]…, 0, len(rows))` DTO slices. `ListWatchlists` uses a `COUNT(...)` aggregate in SQL
  (not a Go-side map), and items are never loaded in full — only a 50-row page. No unbounded
  in-memory item load. Not a finding.
- **`alert_events.go`:** fixed `limit=100`, pre-sized DTO slice, no large blobs. Not a finding.
- **`alert_rules.go` list/get:** `Conditions json.RawMessage` is per-rule DSL (small, user-authored,
  bounded by request-size middleware on write), page limit 20. `parseWatchlistUUIDs` pre-sizes its
  map/slice. Not a finding.
- **Cursor encode/decode (cves.go:132-158, contract.go:107-133, dsl_executor.go:87-111):**
  tiny fixed-size structs; `json.Marshal` on a 2-field struct per page is negligible. Not a finding.
- **Saved-search CRUD (saved_search.go):** `QueryJSON json.RawMessage` is bounded by request-size
  middleware; list capped at 200 with pre-sized slice. Not a finding.

---

## Suspected Bugs (for follow-up)

None observed in the memory lane. (One adjacent observation, not chased: `GetCVESources`'
`CVESourceResponse.NormalizedJSON` aliases the driver-owned `json.RawMessage` backing array; this is
fine for the synchronous serialize-then-discard flow here, but would be a retention hazard if any
caller stored the response past the request — noted only as a design remark.)
