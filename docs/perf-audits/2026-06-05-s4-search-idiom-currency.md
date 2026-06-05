# S4 "Search, CVE read & watchlist" — framework-idiom currency audit

ABOUTME: Performance audit (idiom-currency lane) of the S4 hot read path — CVE search/detail,
ABOUTME: saved searches, watchlists, alert events — checking pgx/huma/stdlib idiom currency on Go 1.26.

**Lane:** framework-idiom currency. **Date:** 2026-06-05. **Slice:** S4 (FULL, hot read path).
**Stack:** Go 1.26 (past version-index `covered_through: Go 1.24` → past-index Heuristic where the
index is silent), huma/v2 2.37.3, chi/v5 5.2.5, **pgx/v5 5.9.2 driving Postgres through the
`database/sql` stdlib adapter** (`stdlib.OpenDBFromPool`), **lib/pq 1.12.3** used only for
`pq.Array` array scanning, squirrel for dynamic SQL.

Version-index entries cited per finding. huma and pgx are third-party; the Go version index covers
stdlib + a handful of common libs (`slices`, `maps`, `errgroup`) — where it is silent on pgx/huma
internals I mark the finding Heuristic / manual-check and do not fabricate version provenance.

## Architectural fact that frames the whole lane

`internal/store/store.go:28-35` builds the store as:

```go
db := stdlib.OpenDBFromPool(pool)   // *sql.DB wrapping the pgxpool
return &Store{pool: pool, db: db, q: generated.New(db)}
```

Every S4 read query — `SearchCVEs` (`cve.go:210`), `ExecuteDSLQuery`/`scanDSLRows`
(`dsl_executor.go:178-261`), `ListWatchlists` (`watchlist.go:131`), `ListWatchlistItems`
(`watchlist.go:251`), and all sqlc-generated reads — flows through `database/sql`
(`*sql.Rows`, `rows.Next()`/`rows.Scan()`, `lib/pq` array codec). The native pgx fast paths
(`pgx.CollectRows` + `pgx.RowToStructByName`, `pgx.Batch`, the pgx binary array codec) are
**reachable only through `s.pool`** (`store.go:39`, already exposed via `Pool()`), but the read
layer never uses them. This is the dominant idiom-currency gap in the slice and the root of the two
MAJOR findings below. It is a deliberate, documented choice (sqlc-via-stdlib), so the realistic win
is selective adoption of pgx native on the hottest dynamic queries, not a wholesale rewrite.

---

## Findings

### MAJOR — Hot CVE search/DSL reads use `database/sql` + `lib/pq` array decode instead of the pgx native row/array fast path

**Location:** `internal/store/cve.go:210-228` (`SearchCVEs`), `internal/store/dsl_executor.go:51-79`
(`scanCVERow`), `dsl_executor.go:243-261` (`scanDSLRows`); driver setup `store.go:28-35`.

**Problem:** The two hottest CVE read queries return `*sql.Rows` from the stdlib adapter and scan
row-by-row into `generated.CVE` with a hand-written 21-field `rows.Scan(...)`, decoding `cwe_ids`
via `pq.Array(&c.CweIds)` (`dsl_executor.go:69`). Three layered costs per request:

1. **stdlib adapter round-tripping.** `database/sql` over the pgx stdlib adapter re-wraps every
   column value through `driver.Value` (`any`-boxing + per-column type assertions) on top of pgx's
   own decode. Querying `s.pool` directly with `pgx.Query` + `pgx.CollectRows` skips the
   `database/sql` layer entirely and uses pgx's binary protocol decode. The Go version index is
   silent on pgx internals (third-party) → **Heuristic / manual-check**, but the extra `any`-boxing
   layer is structural.
2. **`lib/pq` text-format array decode.** `pq.Array(&c.CweIds)` parses the Postgres `text[]`
   wire representation (`{CWE-79,CWE-89}`) by hand in Go for every row. pgx's native `text[]`/array
   codec (binary format) decodes directly into `[]string` without the lib/pq text parser. lib/pq is
   in maintenance-only mode; pgx is the project's primary driver — keeping a second array codec on
   the hot path is the superseded idiom.
3. **Manual scan boilerplate vs generics.** `pgx.RowToStructByName[generated.CVE]` /
   `pgx.CollectRows` (pgx ≥ v5, generic row collection — version index is silent, third-party →
   Heuristic) replace the 21-line positional `rows.Scan` and the `cveColumns`/`scanCVERow`
   column-order coupling that the project already had to fix once (see
   `dev/pitfall-meta-reviews/2026-03-18-section6-arch.md` — a runtime panic from column drift).

**Impact:** Reachability is the highest in the slice — `GET /cves` is *the* primary search endpoint
and `executeSavedSearchHandler` runs the same `cveColumns`/`scanCVERow` path. Per-occurrence cost
is O(rows × columns) with the page bounded to ≤101 rows, so it is a **constant-factor** win
(roughly: one fewer `any`-box + one fewer codec pass per column per row, plus eliminating the lib/pq
array text-parse per row), not a big-O change. Aggregate cost is meaningful because frequency is
high and the corpus is global (every tenant hits it). Not CRITICAL because n-per-request is bounded
and correctness is unaffected.

**Confidence:** Strong-static that the slow layered path exists and that `s.pool` already exposes
the faster API; **Heuristic** on the magnitude of the pgx-native speedup (no runtime profiling here,
and pgx internals are outside the version index).

**Effort:** Contained — rewrite `SearchCVEs` and `scanDSLRows` to take `s.pool.Query(...)` +
`pgx.CollectRows(rows, pgx.RowToStructByName[...])`. Requires a pgx-tagged struct (or
`RowToStructByPos`) and threading the org/bypass `SET LOCAL` through a `pgx.Tx` from the pool
instead of `*sql.Tx` (the helpers `OrgTx`/`WorkerTx` already do this for writes). lib/pq import drops
out of the read path. The squirrel query-building stays unchanged. Touches `internal/store` only;
callers' signatures (`[]generated.CVE`) are preserved.

**Verification plan:** Argue allocations: count `any`-boxes + codec passes per column per row on the
current `database/sql`+`pq.Array` path vs a pgx `CollectRows` path; the array column alone drops a
full text-parse per row. Pin behavior with the existing store integration tests
(`internal/store/cve_test.go`, `dsl_executor_test.go`) which already assert exact field values and
pagination/cursor behavior over a seeded corpus — they must stay green with byte-identical
result rows and identical `next_cursor` output. No fabricated throughput numbers.

---

### MAJOR — `GetCVEDetail` issues 4 sequential round-trips per CVE-detail request instead of one `pgx.Batch` / pipelined fetch

**Location:** `internal/store/cve.go:49-73` (`GetCVEDetail`), consumed by
`internal/api/cves.go:416` (`getCVEHandler`). Same shape in `getCVESourcesHandler`
(`cves.go:503-511`): a `GetCVE` existence check immediately followed by `GetCVESources`.

**Problem:** `GetCVEDetail` runs four queries strictly serially — `GetCVE`, then
`GetCVEReferences`, then `GetCVEAffectedPackages`, then `GetCVEAffectedCPEs` — each a separate
`database/sql` round-trip, each blocking on network latency before the next is issued. The three
child fetches are independent (all keyed on the same `cve_id`, no data dependency between them) and
the existence check only needs to gate the *first* round-trip. pgx exposes `pgx.Batch` /
`conn.SendBatch`, which pipelines all queries in a single network exchange — the canonical pgx idiom
for exactly this "parent + N independent children" fan-out. The Go version index is silent on
`pgx.Batch` (third-party) → **Heuristic / manual-check** on provenance, but pipelining N independent
keyed reads into one round-trip is a structural latency win.

**Impact:** Reachability: every `GET /cves/{cve_id}` detail view. Per-occurrence cost: **4 serial
RTTs collapse to ~1** under a batch — on a pooled remote Postgres this is the dominant latency term
for the endpoint (the queries themselves are single-key index lookups, so RTT, not scan time,
dominates). Not CRITICAL because detail views are lower-frequency than list/search and each query is
cheap server-side; the win is wall-clock latency per detail request, which is a constant
(3 saved RTTs) but on the response critical path.

**Confidence:** Strong-static that the four reads are sequential and independent; **Heuristic** on
the absolute latency saved (depends on RTT, no measurement here).

**Effort:** Contained — convert `GetCVEDetail` to a `pgx.Batch` against `s.pool` (or a single pooled
conn), queuing the four statements and reading results in order. `cves` is global/no-RLS so no
`SET LOCAL` is needed, simplifying the conversion. Child-table sqlc queries can be reused as raw SQL
in the batch. Alternatively (lower effort, smaller win) keep `database/sql` but issue the three
independent child fetches concurrently with a bounded `errgroup` — though `pgx.Batch` is the more
idiomatic and allocation-cheaper path and avoids three concurrent pooled-conn checkouts.

**Verification plan:** Count round-trips before (4) and after (1 batch). Pin behavior with the
existing `GetCVEDetail` store test and the `getCVEHandler` API test — assert the assembled
`CVEDetail` (refs/pkgs/cpes ordering preserved: queries `ORDER BY url_canonical`,
`ecosystem,package_name`, `cpe_normalized` respectively must be retained inside the batch) is
byte-identical. Guard the 404 path: empty batch result for the parent must still yield
`(nil, nil, nil, nil, nil)`.

---

### MINOR — huma list responses (`GET /cves`) marshal the page to an intermediate buffer; raw `writeJSON` handlers already stream

**Location:** huma path: `internal/api/cves.go:315-396` (`listCVEsHandler` returns
`*ListCVEsOutput{Body: *ListCVEsBody}`); huma config `internal/api/server.go:236`. Streaming path
for comparison: `internal/api/contract.go:18-24` (`writeJSON` →
`json.NewEncoder(w).Encode(v)`), used by `executeSavedSearchHandler` (`saved_searches.go:460`),
`listWatchlistsHandler`, `listWatchlistItemsHandler`, `listAlertEventsHandler`.

**Problem:** huma v2's default response handling marshals the `Body` struct to a `[]byte` buffer
before writing it to the `ResponseWriter` (it sets `Content-Length` and writes the whole body),
whereas the project's own `writeJSON` streams field-by-field straight to the socket via
`json.NewEncoder`. So within S4 there are two response-encoding idioms with different allocation
profiles for the same kind of payload (a bounded list of `CVEItem`). The huma marshal-to-buffer
holds the full serialized page (≤101 items) in memory transiently per request. This is a property
of huma's default content negotiation, not project code — the version index covers stdlib JSON, not
huma's transformer → **Heuristic / manual-check**.

**Impact:** Reachability is high (`GET /cves` is the main search endpoint), but per-occurrence cost
is small and bounded: one transient buffer of a ≤101-item page (the same items are already
materialized in the `items []CVEItem` slice regardless). This is a constant, modest extra allocation
+ copy per list request, not a big-O issue. Ranked MINOR because the payload is small and bounded
and huma's buffering also buys `Content-Length` + its OpenAPI/validation contract — switching to a
streaming `huma.StreamResponse` would forfeit that and is a readability/contract regression for an
unmeasured, small gain. Recorded primarily as an **idiom-consistency observation**: the slice mixes
buffered (huma) and streaming (`writeJSON`) encoders for equivalent list payloads.

**Confidence:** Heuristic — huma-internal behavior, no measurement, third-party to the index.

**Effort:** Localized but **not recommended** to "fix" by forcing streaming — it would trade huma's
contract for a sub-page-sized allocation win. The actionable item is awareness, plus ensuring the
non-huma `writeJSON` handlers (which already stream) are not "upgraded" to buffering. No change
proposed.

**Verification plan:** N/A (no change recommended). If ever pursued, measure heap alloc/request for
`GET /cves` with `-benchmem` before/after; only proceed if the buffer shows up materially, which is
unlikely at ≤101 small items.

---

## Idioms checked and found already current (no finding)

- **`slices.Sort` vs `sort.Slice`** (index: Go 1.21): no `sort.Slice` anywhere in the S4 read path;
  ordering is done in SQL `ORDER BY`. No per-call closure-alloc sort to replace. Clean.
- **`min`/`max` builtins** (index: Go 1.21): `clampInt32` (`store.go:155-158`) already uses the
  `min`/`max` builtins, not hand-rolled comparison helpers. Current.
- **`strings.Builder`** (general): the read path does no incremental string concatenation in loops;
  response assembly is struct-field mapping (`cveToItem`, `watchlistToEntry`). Nothing to convert.
- **map/slice generics** (index: Go 1.21 `slices`/`maps`): list handlers pre-size result slices
  correctly with `make([]T, 0, len(rows))` / `make([]CVEItem, len(rows))`
  (`saved_searches.go:178`, `watchlists.go:307,587`, `alert_events.go:105`, `cves.go:382`). No
  unsized `append`-grow loops on the response side. The one place that grows unsized is the store
  `results` slices (`var results []generated.CVE` in `SearchCVEs`/`scanDSLRows`) — but those are
  bounded to ≤101 rows, so a capacity hint there is a cold-path micro-opt below the calibration
  floor; not a finding on its own (it would come for free in the MAJOR pgx-`CollectRows` rewrite,
  which sizes internally).
- **`validEcosystems` map lookup** (`watchlists.go:24-28`): a package-level `map[string]bool`
  literal used for O(1) membership — correct idiom (Go 1.24 Swiss Tables make this even cheaper for
  free; index Go 1.24). No change.
- **Cursor encode/decode**: `base64.RawURLEncoding` + `json.Marshal`/`Unmarshal` of a tiny 2-field
  struct per request — standard, allocation-trivial, bounded. Not a finding.

## Suspected Bugs (for follow-up)

- **Encoding inconsistency between cursor codecs (cross-handler).** `internal/api/contract.go`
  `encodePageCursor`/`decodePageCursor` use `base64.RawURLEncoding` (with a padded-`URLEncoding`
  fallback on decode), and `cves.go` `encodeCursor`/`decodeCursor` use `RawURLEncoding`. But
  `internal/store/dsl_executor.go:93,102` (`encodeDSLCursor`/`decodeDSLCursor`) use
  **padded** `base64.URLEncoding` for the saved-search execute cursor. The three cursor formats are
  not interchangeable; a cursor minted by one path will fail to decode in another if they are ever
  crossed. Not a performance issue and not chased — recording per lane rules (file:line above; the
  DSL executor's padded `URLEncoding` is the odd one out vs the two API-layer `RawURLEncoding`
  codecs).

- **`scanDSLRows` appends to a caller-shared `*[]generated.CVE` with no reset guarantee.** Benign in
  current callers (always a fresh `var results`), but the by-pointer-append signature
  (`dsl_executor.go:243`) is a footgun if a future caller reuses a slice. Not chased.
