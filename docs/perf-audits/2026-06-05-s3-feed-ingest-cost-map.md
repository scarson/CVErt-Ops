# Execution Cost Map — S3 Feed ingestion & adapters

> Architectural awareness, NOT an optimization to-do list. Not every region is a problem.
> Lane scope: `internal/feed/**`, `internal/ingest/**`, `internal/store/feed.go`, plus the
> per-patch write target `internal/merge/**` (invoked once per CanonicalPatch on the ingest path).
> These are HYPOTHESES reasoned from structural signals (loop nesting, per-item callbacks over
> feed-sized collections, fan-out), not measured numbers.

## Structural priors that shape the whole map

- **The dominant multiplier is `merge.Ingest`, called once per CanonicalPatch.** A full NVD
  backfill is ~250k CVEs; OSV/GHSA are thousands–tens-of-thousands; EPSS is ~250k rows daily.
  Every patch that flows out of an adapter hits `merge.Ingest`, and each invocation opens its own
  `database/sql` transaction, takes a `pg_advisory_xact_lock`, re-reads ALL `cve_sources` rows for
  that CVE, recomputes the canonical row from scratch, deletes+re-inserts every child row, and
  issues ~10–15+ separate round-trips. So the realistic time center of S3 is **DB round-trips per
  patch × patch count**, not adapter JSON parsing.
- **`feed_ingest` runs at queue concurrency 1** (`workerPool.Register(...)`, not
  `RegisterWithConcurrency`) — per-feed ingest is sequential. The merge `*sql.DB` is
  `stdlib.OpenDBFromPool` over the shared pgxpool (default `DB_MAX_CONNS=25`), but a single feed run
  drives merges one patch at a time, so wall-clock for a backfill ≈ Σ per-patch latency, serialized.
- **Adapter rate limiters cap request throughput, not CPU.** NVD without an API key is 6s/req ×
  (250k/2000) ≈ 125 pages ≈ 12.5 min just in limiter waits; the merge of those 250k rows is the part
  that scales with corpus size and runs unthrottled.

## Likely time-concentration regions

- **`merge.Ingest` per-patch transaction (the ingest path's center of mass)** — basis: invoked once
  per patch over feed-sized input; each call = `BeginTx` + `pg_advisory_xact_lock` + `UpsertCVESource`
  + optional raw-payload insert + `GetAllCVESources` + `resolve` + hash + `UpsertCVE` +
  `DeleteCVEReferences`/re-insert loop + `DeleteCVEAffectedPackages`/re-insert loop +
  `DeleteCVEAffectedCPEs`/re-insert loop + EPSS staging get/update/delete + FTS upsert. Roughly
  10–15 sequential statements per patch, plus N inserts for N child rows, all serialized by the
  advisory lock and (for one feed) by queue concurrency 1. — confidence: High — also likely flagged
  by the data-access lane (N+1 child-row inserts) and the concurrency lane (advisory-lock +
  single-queue serialization).

- **Per-child-row INSERT loops in `merge.Ingest` (references / affected_packages / affected_cpes)** —
  basis: `for _, ref := range resolved.References { q.InsertCVEReference(...) }` and the analogous
  package/CPE loops issue one round-trip per child row. NVD CVEs routinely carry dozens of CPEs and
  references; an OSV advisory can have many affected-package ranges. Classic N+1 write pattern
  multiplied by patch count. The preceding `DELETE ... WHERE cve_id` + full re-insert on every merge
  (even when child data is unchanged) doubles write volume and generates dead tuples. — confidence:
  High — also likely flagged by the data-access lane (batchable via `CopyFrom`/multi-row insert).

- **`GetAllCVESources` + `resolve` recompute-from-scratch on every write** — basis: the pipeline
  re-reads every source row for the CVE and re-runs full per-field precedence resolution on each
  merge, by design (not incremental). `resolve` does ~8 `slices.Concat(priority, otherSources(...))`
  passes plus union dedup maps for CWEs/refs/packages/CPEs, and `otherSources` allocates+sorts a
  fresh slice each call. Per-patch this is small; over 250k patches × (typically 1–6 sources each) a
  steady allocation + CPU stream. Cost grows with how many sources a CVE accumulates. — confidence:
  Medium — map-only for the recompute design; the repeated `otherSources` allocation/sort may also
  surface in the memory lane.

- **`canonicalizeURL` in `resolve` (per reference, per merge)** — basis: called inside the reference
  union loop for every reference of every source on every merge. It does `url.Parse` +
  `u.Query().Encode()` (re-sorts query params) per URL. NVD/OSV records carry many references, and
  resolution re-runs on every source write for the CVE, so the same URLs get re-parsed repeatedly. —
  confidence: Medium — also likely flagged by the algorithmic/memory lane (repeated parse of stable
  data).

- **`ComputeMaterialHash` (JCS canonicalization + SHA-256) per patch** — basis: once per merge it
  `json.Marshal`s MaterialFields, runs `jsoncanonical.Transform` (a full re-parse/re-serialize of the
  JSON), sorts CWE/CPE/package slices, normalizes CVSS vectors (split/sort/join), then SHA-256s. JCS
  Transform is the heaviest single step — it walks and rebuilds the JSON. Unit cost is modest but it
  is on the per-patch hot path for the whole corpus. — confidence: Medium — map-only; inherent to the
  material-hash design (§5.3).

- **`json.Marshal(patch)` for `normalized_json` + `json.Marshal(wrapper/rec)` for `RawPayload`** —
  basis: each patch is serialized to JSON twice on the way into the DB — once in `merge.Ingest`
  (`json.Marshal(patch)` for `cve_sources.normalized_json`, then a `bytes.ReplaceAll` null-byte scan
  over the result) and once in the adapter (`json.Marshal(wrapper)` / `json.Marshal(rec)` to populate
  `RawPayload`). Reflection-based marshal + a full-buffer null-byte `ReplaceAll` per patch, over
  ~250k patches. — confidence: Medium — also likely flagged by the memory/serialization lane.

- **NVD streaming decode + per-CVE `cveToCanonical` callback** — basis: `parseNVDResponse` does a
  `Token()`/`More()` loop decoding one `nvdVulnWrapper` per record (correct streaming), then
  `cveToCanonical` runs per record with nested loops over descriptions, weaknesses (CWE dedup map),
  configurations→nodes→cpeMatch (3-level nesting with a `cpeSeen` dedup map + `strings.ToLower` +
  `strings.Clone` per CPE), and references. Many `strings.Clone` calls per record are deliberate
  (detaching from the 5+ MB page buffer) but each allocates. Per page bounded (≤2000 records), but it
  runs for every page of the backfill. — confidence: Medium — map-only; the Clone-on-extract is a
  deliberate correctness pattern, not waste.

- **OSV whole-archive scan: `zr.File` loop + `io.ReadAll` per entry + `json.Decode` per entry** —
  basis: `Fetch` iterates every entry in `all.zip` (tens of thousands of advisory files). For each
  non-skipped entry it `entry.Open()` → `io.ReadAll` (full per-file buffer) → `parseAdvisory`
  (`json.NewDecoder(...).Decode`). The `Modified.After(cursor)` pre-filter cheaply skips unchanged
  entries on incremental runs, but the **first full backfill decodes every advisory**, and
  `extractPackageRanges` does a nested `json.Unmarshal` of the events array per range
  (`json.Unmarshal(rng.Events, &events)` then `json.Unmarshal(ev, &obj)` per event). Whole archive is
  also buffered to a temp file first (`DownloadToTemp`, up to 5 GiB cap). — confidence: Medium — also
  likely flagged by the memory lane (per-entry full-read) and data-access lane (whole-feed buffering).

- **OSV/GHSA `ResolveCanonicalID` — per-record alias copy+sort** — basis: called once per advisory;
  allocates a copy of `aliases` and `sort.Strings` it, then runs `cveIDPattern.MatchString` (a
  package-level compiled regexp, good) per alias. Alias lists are short (usually 1–3), so per-call
  cost is tiny, but it is on the per-record path for the entire OSV/GHSA corpus. — confidence: Low —
  map-only; small constant work, listed for completeness.

- **GHSA pagination at 1 req/sec × 100/page** — basis: `rate.NewLimiter(rate.Every(1s),1)` with
  `per_page=100` means a full GHSA backfill is request-latency-bound (thousands of advisories ⇒
  thousands of seconds of limiter waits), and each page's `parseAdvisory` runs nested loops over
  vulnerabilities (synthesizing OSV-style events JSON via `json.Marshal` per affected package), CWEs,
  and references. Per-page CPU is small relative to the 1s wait, so wall-clock here is dominated by
  rate-limit + network, then funneled into the merge bottleneck. — confidence: Medium — map-only
  (rate limit is an external-courtesy constraint, not a code inefficiency).

- **EPSS per-row advisory-locked transaction × ~250k rows/day** — basis: `Apply` streams the CSV
  (good — `bufio` + `csv.Reader` with `ReuseRecord`), but `applyRow` runs **per row**: `BeginTx` +
  `pg_advisory_xact_lock` + `UpdateCVEEPSS` + `UpsertEPSSStaging` + `Commit`. That is ~250k separate
  transactions, each with its own advisory-lock round-trip, every day. The single largest fixed daily
  DB-round-trip count in S3, sequential within the `epss_ingest` handler. The per-row transaction is a
  deliberate TOCTOU-safety choice (§5.3), so it is inherent — but it is unambiguously the daily
  steady-state hot region. — confidence: High — also likely flagged by the data-access lane (per-row
  tx, batchable) and concurrency lane (advisory lock per row).

- **Realtime alert hash-diff: 2× `GetCVEMaterialHash` per patch when alerts enabled** — basis: in
  `ingest/handler.go`, when `eval` and `hashReader` are wired (production path via
  `HandlerWithAlerts`), each patch incurs a `GetCVEMaterialHash` read **before** merge and another
  **after** merge — two extra DB round-trips per patch on top of the merge's own ~10–15. For a 250k
  backfill that is ~500k additional point reads interleaved with the merge writes. — confidence:
  High — also likely flagged by the data-access lane (the post-merge hash is already computed inside
  `merge.Ingest` and could be returned instead of re-read).

- **Per-page cursor persist (`UpsertFeedSyncState`) inside the pagination loop** — basis: the handler
  persists sync state after every page for crash recovery. For NVD (~125 pages) this is ~125 extra
  writes per run — negligible next to per-patch merge cost. Listed only to note it scales with page
  count, not item count. — confidence: Low — map-only.

- **Generic adapter buffered path: `io.ReadAll` + `gjson.GetBytes`/`ForEach` + per-field `gjson.Get`**
  — basis: `fetchJSONBuffered` reads the whole body (up to 50 MB) then `mapRecord` calls
  `gjson.Get(raw, path)` once **per configured field per record** — gjson re-scans the record's raw
  JSON from the start for each field lookup (no compiled path / no single-pass extraction). With ~10
  mapped fields, that is ~10 independent scans of each record. The streaming path
  (`fetchJSONStream`) avoids whole-body buffering but still does per-field `gjson.Get` re-scans via
  `gjson.ParseBytes(raw)` per record. Only affects admin-configured generic feeds (volume varies). —
  confidence: Medium — also likely flagged by the algorithmic lane (repeated re-scan per field).

## Notes for architecture

- **The merge pipeline, not the adapters, is where S3 spends its time.** Adapter JSON parsing is
  already streamed where it matters (NVD, GHSA, generic-stream) and is bounded per page. The
  multiplier that actually scales with corpus size is the per-patch DB transaction in `merge.Ingest`.
  If a future scaling effort targets ingest throughput, the highest-leverage structural questions are:
  (a) can child-table writes (`references`/`packages`/`cpes`) move from per-row `INSERT` loops to
  `pgx.CopyFrom` or multi-row `INSERT`? (b) can the unconditional delete+re-insert of child tables be
  gated on a cheap "did child data change" check (it already has the `material_hash` signal computed)?
  Observations, not directives — the current design favors correctness/simplicity and is reasonable
  for incremental syncs where per-page item counts are small.
- **EPSS daily apply and the merge child-write loops share the same shape** (per-item DB round-trip in
  a loop). If batching is ever pursued, both are candidates; EPSS has the larger fixed daily count
  (~250k) but a simpler row shape, so it may be the cleaner place to demonstrate a batched/`COPY`
  approach. The per-row advisory lock is the constraint to respect (§5.3 TOCTOU) — any batching must
  preserve the lock semantics, which is non-trivial.
- **The 2× hash read per patch on the alerts-enabled path** is the cheapest structural win to keep in
  mind: `merge.Ingest` already computes the post-merge `material_hash`; returning it (or a
  changed-bool) would let the handler drop one of the two `GetCVEMaterialHash` round-trips and the
  pre-read could be folded into the merge transaction. Map-only observation — verify against the
  realtime-eval contract before acting.
- **`resolve` re-reads and re-resolves all sources on every single source write.** For a CVE that
  accumulates 6 sources, ingesting all 6 means resolve runs 6 times over a growing source set
  (1+2+3+4+5+6 source-reads total). Inherent to the "recompute from scratch" design (§5.1) and
  correct; flagged only so the quadratic-in-source-count shape is visible. Source counts per CVE are
  small and bounded, so this is not alarming — just structurally noted.

## Suspected Bugs (for follow-up)

None observed in this lane. (The pipeline's correctness patterns — advisory locks, `IS DISTINCT FROM`
guards, always-drain EPSS staging, explicit per-iteration `rc.Close()` in OSV, `strings.Clone` on
extracted fields — are consistent with the documented pitfalls and were not analyzed adversarially
here; this lane is descriptive.)
