# S1 Merge & corpus write path — algorithmic complexity & data structures

Lane: **algorithmic**. Slice S1 (FULL depth, HOT). Reviewed the actual source of
`internal/merge/{pipeline,resolve,hash,advisory,fts}.go`, `internal/store/cve.go`, the SQL in
`internal/store/queries/cves.sql` + `vendor_enrichment.sql`, the DDL in
`migrations/000002_create_cve_core.up.sql`, and the frequency driver in
`internal/ingest/handler.go` (per-patch merge loop) + the registration in `cmd/cvert-ops/main.go`.

**Hot-path model.** `merge.Ingest` is called **once per source write per CVE** from the ingest
pagination loop (`internal/ingest/handler.go:163-211`). A full feed sync touches up to ~250k CVEs,
and each CVE is written by every feed that carries it (NVD, MITRE, OSV, GHSA, KEV, MSRC, Red Hat —
up to ~7 scalar-precedence sources, more counting EPSS/unknown). The pipeline is explicitly
**recompute-from-scratch**: every source write re-reads ALL `cve_sources` rows for the CVE
(`GetAllCVESources`, `pipeline.go:126`), JSON-unmarshals each, and rebuilds the canonical row +
child tables + FTS document from zero. This recompute-per-write design is the structural root of the
findings below.

---

### [CRITICAL] Re-resolve-from-scratch on every source write makes a full corpus sync super-linear in source count (O(k²) JSON-unmarshal + union work per CVE)

**Location:** `internal/merge/pipeline.go:126-133` (`GetAllCVESources` + `resolve`), driven by the
per-patch loop in `internal/ingest/handler.go:163-211`; `resolve()` body `internal/merge/resolve.go:84-275`.

**Problem:** Each `Ingest` call reads **all** `cve_sources` rows for the CVE and `resolve()`
JSON-unmarshals every one (`resolve.go:88-103`) before rebuilding every field. During a multi-feed
sync, a CVE with `k` sources gets `k` independent source writes over the sync window. The i-th write
unmarshals `i` source blobs and re-unions all references/CWEs/packages/CPEs across them. Summed over
the `k` writes for that CVE this is `1+2+…+k = O(k²)` JSON unmarshals and `O(k²)` union passes —
versus `O(k)` if the resolve consumed only the newly-written patch plus an already-materialized
canonical state. The unmarshal is the dominant per-source cost: `cve_sources.normalized_json` is the
full normalized CanonicalPatch (description, all references, all CPEs, all package ranges), and NVD
CVEs routinely carry tens to hundreds of CPEs/references, so each unmarshal is far from free.

**Impact:** Reachability: certain — this is THE corpus write path, every feed sync, every CVE.
Frequency: up to ~250k CVEs × up to ~7 scalar sources (plus re-syncs on every feed refresh
cycle). Per-occurrence: `resolve` does `k` `json.Unmarshal` of multi-KB JSONB blobs + `k` full
union rebuilds, and the whole thing repeats `k` times per CVE → aggregate `O(k²)` unmarshals across
the sync. With `k≈7` the constant is ~4× the minimal `O(k)`; the cost is real because the
per-unmarshal payload is large and this multiplies across the entire corpus. This is the single
largest algorithmic cost in the slice. **Note:** changing it is an architectural change to the
merge contract (incremental merge vs. recompute) — CLAUDE.md documents recompute-from-scratch as a
deliberate correctness decision (per-field precedence + late-binding PK migration depend on seeing
all sources). So this is flagged as the marquee algorithmic cost with the caveat that the fix
requires Sam's design sign-off, not a local rewrite.

**Confidence:** Strong-static (the read-all + unmarshal-all + rebuild-all structure is explicit in
the code; the per-write invocation is explicit in the ingest loop).

**Effort:** Cross-cutting + high-effort — would require either an incremental merge that mutates a
materialized canonical state from the single new patch, or batching all of a CVE's source writes
within one sync into a single resolve. Both change the `Ingest` contract and interact with the
advisory-lock / PK-migration logic. Do NOT attempt without design agreement.

**Verification plan:** Complexity argument: count `json.Unmarshal` calls in `resolve` as a function
of sources-present; show it equals current-source-count, then sum over the `k` writes per CVE to get
the quadratic. Benchmark: `BenchmarkIngestSourceFanout` that ingests N sources for one CVE
sequentially and counts total unmarshals / wall time, comparing `k=1,3,7`. Correctness guard:
`pipeline_integration_test.go` already pins that the final canonical row after all sources is
identical regardless of write order — any incremental rewrite must keep that test green, plus the
PK-migration and tombstone integration cases.

---

### [MAJOR] `resolve` rebuilds and re-sorts the "other sources" list on every field that uses precedence — repeated `otherSources` + `slices.Concat` per resolve call

**Location:** `internal/merge/resolve.go:142, 156, 239` (three `slices.Concat(prio, otherSources(patches, prio))`),
plus `firstStr`/`firstStrPtr` calling `otherSources` again at `resolve.go:288, 308`; `otherSources` itself
`resolve.go:320-333`.

**Problem:** `otherSources` allocates a `map`, scans all patches, builds a slice, and `sort.Strings`
it — O(s log s) for `s` patches. It is invoked **separately for each precedence-resolved field**:
CVSSv3 (line 142), CVSSv4 (line 156), affected packages (line 239), and again inside every
`firstStr`/`firstStrPtr` call for Status, Description, Severity (×2). That's ~7 independent rebuilds
of the same "sources not in a priority list" set per `resolve` call, each with its own map alloc +
sort, and three of them are wrapped in `slices.Concat` which allocates a fresh combined slice too.
The set of patch source-names is fixed for the duration of one `resolve`; this is pure recomputation
of an invariant value inside the function.

**Impact:** Reachability: certain — runs on every `Ingest`. Frequency: same as the write path
(~250k CVEs × sources × re-syncs). Per-occurrence: ~7 map allocations + ~7 `sort.Strings` + 3
`slices.Concat` allocations per resolve, all redundant. `s` is small (≤ ~8), so each sort is cheap,
but the allocation churn (maps + slices) is multiplied across the entire corpus on every sync — a
constant-factor GC/alloc tax on the hottest function. Hoisting `otherSources(patches, prio)` once per
priority list (there are only 3 distinct priority lists: status, cvss, pkg) collapses ~7 rebuilds to
3 and removes the per-field `slices.Concat` allocations.

**Confidence:** Strong-static.

**Effort:** Localized — compute `cvssOthers`, `statusOthers`, `pkgOthers` (and the concatenated
iteration orders) once near the top of `resolve` and reuse; `firstStr`/`firstStrPtr` take the
precomputed "others" slice instead of recomputing. One function + two helper signatures.

**Verification plan:** Allocation argument: count `otherSources`/`slices.Concat` calls per resolve
before (≈7+3) and after (3+0); confirm via `-benchmem` `allocs/op` drop on a resolve microbenchmark
with 6–8 sources. Correctness guard: `resolve_test.go` + `resolve_custom_test.go` pin per-field
precedence including unknown-source tie-breaks — must stay green (iteration order over "others" must
remain the sorted order the tests assume).

---

### [MINOR] `firstStr`/`firstStrPtr` recompute `otherSources` per call instead of sharing with the caller's already-built ordering

**Location:** `internal/merge/resolve.go:280-316` (the `otherSources` calls at 288 and 308), invoked from
`resolve.go:109, 129, 170, 177`.

**Problem:** This is the same recomputation as the MAJOR above, isolated to the helper layer:
Status, Description, and Severity (twice) each call `firstStr`/`firstStrPtr`, and each of those
independently calls `otherSources(patches, priority)`. If the MAJOR fix passes a precomputed
"others" slice down, this disappears; calling it out separately because it's the part reachable even
if only the scalar-precedence helpers are touched. Standalone, deduplicating just these saves 3–4
map-alloc+sort cycles per resolve.

**Impact:** Reachability: certain. Frequency: corpus-wide. Per-occurrence: 3–4 redundant
map+sort builds; small `s` so individually cheap, aggregate alloc tax only. Subsumed by the MAJOR
finding's fix — listed so it isn't missed if that fix is scoped down.

**Confidence:** Strong-static.

**Effort:** Localized (folds into the MAJOR fix).

**Verification plan:** Same resolve microbenchmark `allocs/op`; same `resolve_test.go` precedence
guards.

---

### [MINOR] Per-row child-table INSERT loop (references/packages/CPEs) — O(rows) round-trips per merge, re-executed on every source write

**Location:** `internal/merge/pipeline.go:193-240` (loops calling `InsertCVEReference`,
`InsertAffectedPackage`, `InsertAffectedCPE` one row at a time); queries `cves.sql:93-108`.

**Problem:** After the delete-all, each resolved reference / package / CPE is inserted with its own
`ExecContext` round-trip inside a Go `for` loop. A heavily-referenced NVD CVE can have tens to
hundreds of references and CPEs, so that's tens-to-hundreds of individual INSERT round-trips — and
because the whole child set is delete+re-inserted on **every** source write (recompute-from-scratch),
the same rows are re-inserted `k` times across a sync. This is an N-row-per-op pattern, not strictly
an algorithmic-complexity defect, but it sits squarely on the hot write path and the row counts are
unbounded by feed content. (Primarily a data-access concern — flagging here at MINOR because the
multiplier is the same recompute-per-write structure this lane owns; the data-access lane should own
the batch-insert remedy.)

**Impact:** Reachability: certain, every merge. Frequency: corpus-wide × source fan-out.
Per-occurrence: O(refs + pkgs + cpes) DB round-trips, repeated `k` times per CVE. For a CVE with
100 CPEs and 7 sources that's ~700 CPE INSERT round-trips over a sync where the canonical result is
100 rows. Batching (multi-row INSERT / `pq.CopyFrom`-style) collapses each loop to one round-trip.

**Confidence:** Strong-static.

**Effort:** Contained — needs new multi-row insert queries (sqlc `:copyfrom` or array-unnest INSERT)
+ call-site changes in `pipeline.go`; ON CONFLICT DO NOTHING dedup semantics must be preserved.

**Verification plan:** Count round-trips per merge before (= row count) vs after (= 1 per child
table). Correctness guard: `pipeline_integration_test.go` child-table assertions (dedup by
`url_canonical` / `cpe_normalized`, package set) must stay green.

---

### [MINOR] `ComputeMaterialHash` re-sorts `CWEIDs` that `resolve` already sorted — duplicate sort on every merge

**Location:** `internal/merge/hash.go:57` (`sort.Strings(f.CWEIDs)`) vs `internal/merge/resolve.go:213-217` (CWE union already `sort.Strings`-ed before being placed on `ResolvedCVE.CWEIDs`).

**Problem:** The resolver builds the CWE union into a deduped slice and sorts it (`resolve.go:217`). That same slice is then passed straight into `ComputeMaterialHash` (`pipeline.go:143`), which re-sorts it (`hash.go:57`). The `AffectedCPEs` and `AffectedPkgs` sorts in `ComputeMaterialHash` are load-bearing (those slices arrive in priority/insertion order), but the CWE sort is pure duplicate work on an already-sorted slice, executed on every merge.

**Impact:** Reachability: certain, every merge. Per-occurrence: one redundant `sort.Strings` over a short, already-ordered slice. Constant-factor, small n — but unconditional on the hottest write path.

**Confidence:** Strong-static (`resolve.go:217` is the sole producer of the `CWEIDs` reaching the hash, and it sorts).

**Effort:** Localized — pick a single owner for the CWE sort. Either drop the resolver's sort (and let the hash own canonical ordering) or drop the hash's sort (and treat the resolver's contract as guaranteed). Don't do both halfheartedly.

**Verification plan:** Confirm no other producer mutates `ResolvedCVE.CWEIDs` between `resolve` and `ComputeMaterialHash`; keep `hash_test.go` order-independence tests and `pipeline_integration_test.go` material-hash assertions green. Net: one fewer sort per merge.

---

### Suspected Bugs (for follow-up)

- **Double per-patch hash read on the realtime path (perf-shaped, borderline in-scope).**
  `internal/ingest/handler.go:167-210`: when `eval != nil`, every patch triggers a
  `GetCVEMaterialHash` DB round-trip **before** merge and another **after** merge, purely to detect
  whether the hash changed. The merge transaction already computes `materialHash` and the
  `UpsertCVE` SQL already knows (via the `IS DISTINCT FROM` CASE at `cves.sql:21-25`) whether it
  changed. So the hot path does 2 extra single-row SELECT round-trips per patch — corpus-wide ×
  source fan-out — to recover a fact the merge already had. This is recomputation of a value the
  write path computes, but the value lives across a package boundary (merge returns only `error`),
  so fixing it means changing `merge.Ingest` to report "material changed" — a contract change.
  Recording here rather than chasing; if the marquee CRITICAL is reworked, plumbing a
  `materialChanged bool` out of `Ingest` would eliminate these two reads for free.

- **`collectPackageNames` vs `JoinForFTS`/`strings.Join` duplication (not a bug, noted).**
  `pipeline.go:283-288` builds FTS package names via `collectPackageNames` (dedups) then
  `strings.Join`, while `fts.go:JoinForFTS` exists but is unused here. No correctness issue; just an
  unused helper. Out of lane, noted only.

No other correctness bugs observed in the read paths examined.
