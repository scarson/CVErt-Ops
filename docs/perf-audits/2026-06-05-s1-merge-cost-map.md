# Execution Cost Map — S1 Merge & corpus write path

> Architectural awareness, NOT an optimization to-do list. This maps where wall-clock time
> most plausibly concentrates when ingesting large (~250k-CVE) feeds across N sources each.
> Regions are reasoned from code structure, not measured (no profiler in this container).

## Frequency model (the multiplier behind everything below)

Confirmed from `internal/ingest/handler.go` + `internal/merge/pipeline.go`:

- The ingest loop calls `merge.Ingest` **once per patch** — i.e. once per (CVE × source × page-occurrence).
  For a full sync of 8 sources over a 250k-CVE corpus this is on the order of **10^6 `Ingest` invocations**,
  each its own `BeginTx … Commit` round-trip.
- Each `Ingest` is **not incremental**: it re-reads ALL `cve_sources` rows for the CVE and recomputes the
  entire canonical row + child tables + hash + FTS document from scratch (pipeline.go:126-291). So per-CVE
  work scales with `S` = number of sources already present for that CVE, and the corpus-wide cost is
  roughly `Σ over writes (S_cve)` — superlinear in source count because every new source write reprocesses
  all prior sources for that CVE.
- The realtime-eval path wraps each merge with **two extra single-row round-trips** (`GetCVEMaterialHash`
  before + after, handler.go:169 & 194) whenever an evaluator is attached.

So the dominant axis is **DB round-trips per `Ingest`**, multiplied by ~10^6 invocations. CPU work (JCS,
sha256, sorts) is real but secondary to the round-trip count and the re-read/re-insert amplification.

## Likely time-concentration regions

- **Per-`Ingest` DB round-trip count (the delete+re-insert child-table loops)** — basis: each invocation
  issues a fixed spine of statements (advisory lock, upsert source, optional raw payload, GetAllCVESources,
  upsert cve, optional tombstone, 3× DELETE child tables, 1 UpsertVendorEnrichment?, GetEPSSStaging,
  UpdateCVEEPSS?, DeleteEPSSStaging, UpsertCVESearchIndex) **plus one INSERT per reference, per affected
  package, and per CPE** (pipeline.go:193-240). For CVEs with many references/CPEs (NVD rows routinely have
  tens of CPEs and references) this is dozens of sequential `ExecContext` round-trips per `Ingest`, each a
  separate network/lock/parse cycle. Multiplied across 10^6 invocations this is the single largest plausible
  time sink. The DELETE-all-then-reinsert-all pattern re-writes every child row on every source write even
  when the child set is unchanged. — confidence: High — also flagged by data-access lane (round-trip
  amplification, write amplification) and likely algorithmic lane (re-resolve from scratch).

- **`GetAllCVESources` re-read + full `resolve()` recompute on every write** — basis: pipeline.go:126-133
  re-fetches all source rows (TOASTed `normalized_json` blobs) and resolve.go:84-275 `json.Unmarshal`s every
  one of them into a `CanonicalPatch` on every single source write, then runs ~10 per-field precedence passes
  plus union/dedup map-builds over all patches. Cost per write grows with the number of sources for that CVE
  and the size of each normalized_json. The JSON unmarshal of all sources is likely the hottest CPU step
  inside resolve. — confidence: High — also flagged by algorithmic lane (non-incremental recompute) and
  memory lane (per-write allocation of all patches + maps).

- **FTS tsvector rebuild + GIN index write under the advisory lock** — basis: `UpsertCVESearchIndex`
  (cves.sql:110-122) calls `to_tsvector('english', …)` four times and `setweight`/concatenates inside the
  INSERT, then writes a GIN-indexed `tsvector`. tsvector construction is CPU-heavy server-side and GIN
  updates are write-amplifying. The `IS DISTINCT FROM` guard avoids the index write only when the document is
  byte-identical — but the tsvector is still *computed* on every call to evaluate the guard. Description text
  (weight A) dominates token count. — confidence: High — also flagged by data-access lane (GIN write
  amplification).

- **Advisory-lock-serialized critical section spanning the whole transaction** — basis: pipeline.go:60 takes
  `pg_advisory_xact_lock` as step 1 and holds it until `tx.Commit()` at line 293. Every per-row child INSERT,
  the FTS tsvector build, the EPSS apply, and all round-trips happen *inside* the lock. Concurrency is
  per-CVE so unrelated CVEs don't contend, but the lock-hold *duration* equals the full multi-round-trip
  transaction, so any tail latency in child inserts/FTS extends the window during which a same-CVE writer
  (e.g. EPSS adapter sharing the `cve` domain key, advisory.go:36) blocks. Throughput ceiling = serial
  transaction latency per CVE. — confidence: Medium — also flagged by concurrency lane (lock-hold scope).

- **JCS canonicalization + sha256 of MaterialFields, every write** — basis: hash.go:51-95 marshals
  MaterialFields to JSON, runs `jsoncanonical.Transform` (a full re-parse + re-serialize of the JSON), then
  sha256. This runs unconditionally on every `Ingest` (pipeline.go:136). The JCS Transform does its own
  tokenize/sort/re-emit pass over the document; for CVEs with large `affected_packages`/`affected_cpes`/`cwe_ids`
  arrays the marshal+transform dominates the hash cost. Per-occurrence cost is modest, but ×10^6 invocations
  makes it a real aggregate CPU line. — confidence: Medium — also flagged by memory lane (marshal + Transform
  allocate two intermediate byte buffers per write) and algorithmic lane.

- **In-`resolve` array sorts and map-dedup builds** — basis: resolve.go sorts CWEs (217), builds dedup maps
  for references (220-234), packages (238-253), CPEs (256-272), and `otherSources` re-sorts per call
  (320-333, invoked once per `firstStr*`/CVSS/pkg pass → multiple times per resolve). Plus a second round of
  sorts inside `ComputeMaterialHash` (hash.go:57-68) over the same data. The arrays are small per CVE
  (bounded n), so each sort is cheap; the concentration is the *count* of these passes × 10^6 invocations,
  not any single sort's complexity. — confidence: Medium — map-only (bounded-n; aggregate-only concern, not a
  per-call hotspot).

- **Two extra round-trips per patch for realtime-eval hash diffing** — basis: handler.go:169 & 194 read
  `material_hash` before and after each merge via `GetCVEMaterialHash` (a standalone `QueryRowContext`,
  cve.go:32-44) whenever an evaluator is attached. That's +2 single-row queries on top of the ~dozens inside
  `Ingest`, on every patch. Marginal next to the child-insert spine, but it rides the same 10^6 multiplier and
  is pure overhead on the write path. — confidence: Medium — also flagged by data-access lane.

- **Per-`Ingest` transaction begin/commit overhead** — basis: every patch opens and commits its own
  transaction (pipeline.go:52, 293). At 10^6 invocations the fixed BEGIN/COMMIT + WAL-flush-per-commit cost is
  a structural floor independent of the work inside. Batching multiple patches per transaction is precluded by
  the per-CVE advisory-lock + per-CVE recompute design, so this is inherent to the current architecture. —
  confidence: Medium — also flagged by data-access lane (commit/WAL frequency).

## Notes for architecture

- The cost structure is **round-trip-bound, then recompute-bound, then CPU-bound** in that order. The biggest
  lever by structure is the number of statements per `Ingest` (especially the unconditional DELETE-all +
  per-row re-INSERT of references/packages/CPEs) and the re-read+re-resolve-from-scratch model — both scale
  with corpus size × source count, not with the size of the actual delta.
- The `IS DISTINCT FROM` guards on `cves`, `cve_sources`, and `cve_search_index` already suppress *write*
  amplification (dead tuples / GIN churn) when content is unchanged — but they do **not** suppress the
  *compute* (tsvector build, hash, resolve) or the round-trip to evaluate the guard. The guards protect
  storage, not CPU or round-trips.
- Child-table writes have no such guard: they unconditionally DELETE then re-INSERT every row each write, so
  they always churn dead tuples and indexes even when the resolved child set is identical to what's stored.
  This is the clearest structural mismatch between work done and work needed.
- The advisory lock correctly scopes contention to same-CVE writers, so the concurrency concern is lock-hold
  *duration* (set by the multi-round-trip transaction), not lock *contention breadth*.
- JCS `Transform` re-parses already-valid JSON that the code just produced via `json.Marshal`; structurally
  the canonicalization is doing a parse the producer could have avoided, but this is a CPU micro-line, not a
  dominant region.

## Suspected Bugs (for follow-up)

None observed in the hot path during this cost-mapping pass. (`buildAffectedPkgKeys` drops the `LastAffected`
field from the material hash while `affectedPkgKey` keys packages by introduced/fixed only — this looks
intentional per the §5.3 "minimal key" comment, not a bug; noting only because it affects what counts as a
material change.)
