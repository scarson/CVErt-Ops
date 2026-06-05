# S1 Merge & corpus write path — memory & allocation lane

**Date:** 2026-06-05
**Lane:** memory & allocation (slice S1, FULL/HOT)
**Scope read:** `internal/merge/pipeline.go`, `internal/merge/resolve.go`, `internal/merge/hash.go`,
`internal/merge/fts.go`, `internal/merge/advisory.go`, `internal/store/cve.go`,
`internal/store/queries/cves.sql`, `internal/feed/interface.go`, `internal/ingest/handler.go`.
**Profiling:** none available in this container (no Docker/testcontainers). All findings are static. Never `Measured`.

## Hot-path model

`merge.Ingest` runs **once per source write** while ingesting feeds of ~250k CVEs. Per call it:
1. `json.Marshal(patch)` + `bytes.ReplaceAll` to strip NULs.
2. Reads **all** `cve_sources` rows for the CVE (`GetAllCVESources`).
3. `resolve(sources)` — `json.Unmarshal` of **every** source's `normalized_json`, builds ~7 maps + several union slices.
4. `ComputeMaterialHash` — sorts slices, `json.Marshal`, **JCS `Transform` (re-parses the JSON into a `map`/sorts/re-emits)**, `sha256`.
5. ~6–15 child-row DB inserts.

Steps 1, 3, 4 are pure CPU+allocation and are the focus of this lane. The per-call allocation
footprint is dominated by **double JSON marshal/unmarshal cycles** and the **JCS re-parse**, both of
which churn fresh buffers and maps on every one of the ~250k×(#sources) writes.

---

## Findings

### [MAJOR] Material hash re-serializes through JCS, doubling JSON work and re-parsing into a transient map on every write
**Location:** `internal/merge/hash.go:81-94` (`ComputeMaterialHash`)
**Problem:** The hash is computed as `sha256(jcs(json.Marshal(f)))`. `json.Marshal(f)` produces a
`[]byte`, then `jsoncanonical.Transform(raw)` **parses that JSON back into an in-memory structure,
recursively sorts object keys, and re-serializes** to canonical bytes. `MaterialFields` is a fixed
Go struct whose field order is known at compile time — its JSON output is *already* deterministic for
scalars, and the only ordering nondeterminism is in the slice fields, which the function **already
sorts explicitly** (`sort.Strings(f.CWEIDs)`, `sort.Strings(f.AffectedCPEs)`, `sort.Slice(...)` on
packages, and `normalizeCVSSVector`). JCS exists to canonicalize *arbitrary* JSON with unknown key
order; here the key order is fixed by the struct and the array order is pre-sorted, so the second
parse+sort+re-emit pass is redundant work. Each call allocates: the `json.Marshal` buffer, then JCS's
full parse (a `map[string]any`/token tree + a fresh output buffer). That is two complete
serialization passes and a transient decoded tree per write.
**Impact:** Reachable on **every** `Ingest` (250k CVEs × N sources each). Per occurrence: one extra
full JSON parse into a dynamic structure (the costliest JSON mode — `map[string]any`/`any` boxing per
field, per the serialization pack) plus a second output buffer, on top of the `json.Marshal`. For a
record with dozens of CPEs/packages this is the largest single allocation source in the hash step.
Eliminating the JCS pass roughly halves the serialization allocation of the hash and removes the
dynamic-tree allocation entirely.
**Confidence:** Strong-static (the struct field order is fixed; arrays are pre-sorted in the same
function; JCS's contract is parse→sort-keys→re-emit).
**Effort:** Contained — requires confirming that `encoding/json`'s struct emission already matches the
canonical form the hash needs (it does for this struct: stable field order, no floating-point
re-formatting beyond Go's default, no unsorted maps), then hashing the `json.Marshal` output directly
(`sha256.Sum256(raw)`), or feeding `raw` to the hasher via an `io.Writer` to skip the intermediate
entirely. Must be done carefully because it changes the hash value of every CVE.
**Verification plan:** Benchmark `ComputeMaterialHash` with `-benchmem` on a representative
`MaterialFields` (many CPEs/CWEs) before/after dropping JCS; expect roughly a halving of bytes and a
large drop in alloc count from removing the dynamic parse tree. **Correctness guard:** this changes
`material_hash` values, so it is NOT a transparent refactor — `hash_test.go` golden values must be
regenerated and a one-time full re-hash of the corpus is implied. Treat as a deliberate hash-format
change, not a silent optimization; pin the *new* determinism property (same input → same hash,
order-independence of arrays) with the existing permutation tests in `hash_test.go`. **If keeping JCS
is required for spec-compliance reasons, this stays as documented overhead** — record the decision
rather than silently removing it.

### [MAJOR] `normalized_json` is marshaled and unmarshaled in full on every write, even though only the writing source's patch changed
**Location:** `internal/merge/pipeline.go:45` (`json.Marshal(patch)`) + `internal/merge/resolve.go:88-103`
(`json.Unmarshal` of every source in the loop)
**Problem:** `Ingest` marshals the incoming `patch` to `normalized_json` (step 2), writes it, then
immediately re-reads **all** sources and `json.Unmarshal`s every one of them inside `resolve` —
including the one it just serialized. For a CVE present in 5 sources, that is 1 marshal + 5 unmarshals
per write, each allocating a fresh `CanonicalPatch` with its nested `[]ReferenceEntry`,
`[]AffectedPackage`, `[]AffectedCPE`, `[]string` slices and `json.RawMessage` fields. None of these
intermediate `CanonicalPatch` values are pooled or reused; they are built and discarded every write.
The marshal→DB→unmarshal round-trip for the *current* patch is pure churn: the handler already holds
the typed `patch` in memory.
**Impact:** Reachable on every `Ingest`. Per occurrence the unmarshal cost scales with source count ×
payload size; popular CVEs (NVD+MITRE+OSV+GHSA+KEV+RedHat) unmarshal 6 full records every time *any*
one of them is written. Over a 250k-CVE backfill with multiple feeds this is the dominant steady-state
allocator in `resolve`.
**Confidence:** Strong-static (the read-all-then-unmarshal-all pattern is explicit; the recompute is
documented as from-scratch).
**Effort:** Cross-cutting to remove fully (would require caching decoded patches keyed by
`(cve_id, source_name)` with invalidation, or passing the just-decoded current patch into `resolve`
to skip one unmarshal). A **Localized** partial win is available: `resolve` could accept the live
`patch` and reuse it instead of re-decoding the row it just wrote, saving one unmarshal per call.
The "recompute from scratch on every write" design is mandated (CLAUDE.md / §5.1) so the read-all of
*other* sources is required; only the self-round-trip is avoidable.
**Verification plan:** Benchmark `resolve` with `-benchmem` over a synthetic 6-source CVE; count
`CanonicalPatch` allocations. **Correctness guard:** `pipeline_integration_test.go` and
`resolve_test.go` must show identical resolved output whether the current patch is re-decoded or
reused — the decoded form must be byte-identical to the stored `normalized_json` (it is, since the
same `patch` was just marshaled to it, modulo the NUL strip which only affects payloads containing
`\x00`). Flag the NUL-strip edge case in the guard test.

### [MINOR] `resolve` rebuilds 7 throwaway maps and calls `slices.Concat`/`otherSources` repeatedly per write
**Location:** `internal/merge/resolve.go:85` (`patches` map), `:142,:156,:239` (`slices.Concat(...otherSources(...))`),
`:205` (`cweSet`), `:220` (`refSeen`), `:238` (`pkgSeen`), `:256` (`cpeSeen`), `:320-333` (`otherSources`)
**Problem:** Each `resolve` allocates a `map[string]feed.CanonicalPatch` plus four
`map[string]struct{}` dedup sets (CWE/ref/pkg/CPE) and several result slices, all short-lived.
Additionally `otherSources(patches, priority)` is recomputed and a new slice allocated **three times**
(CVSSv3, CVSSv4, packages) — each call builds a `known` map and a sorted `others` slice, then
`slices.Concat` allocates yet another backing array joining priority+others. The `known` set is also
rebuilt from the same constant priority list every call. With at most ~8 sources the per-map cost is
small, but the count of distinct allocations per write is high (10+ maps/slices) and every one is
reached on every write.
**Impact:** Reachable every `Ingest`; n is provably small (≤8 sources, the named-source priority lists
are fixed), so this is constant-factor allocation-count churn rather than a complexity problem. Real
but secondary to the two JSON findings above. The repeated `otherSources`/`slices.Concat` (3× per
call, each two allocations) is the most concrete sub-item.
**Confidence:** Strong-static.
**Effort:** Localized. Compute `otherSources(patches, cvssPriority)` once and reuse for v3+v4 (same
priority list); precompute the `known` sets for the three fixed priority lists as package-level
`map[string]struct{}` values built in `init`/`var` (they never change), turning `otherSources` into a
single allocation. Dedup-set maps can be pre-sized with `make(map[...]struct{}, n)` where n is the
summed source slice length. Do **not** over-engineer pooling for ≤8-entry maps.
**Verification plan:** `-benchmem` on `resolve`; expect a drop in alloc *count* (fewer maps/concats),
small bytes change. **Correctness guard:** `resolve_test.go` precedence and union tests must stay
green — particularly the "unknown source" ordering, since hoisting the `known` sets must preserve the
sorted `others` order.

### [MINOR] `normalizeCVSSVector` splits and re-joins even when the vector is already canonical or empty-but-present
**Location:** `internal/merge/hash.go:106-118`, called at `:53-54`
**Problem:** Both v3 and v4 vectors are run through `strings.Split` (allocates a `[]string`) +
`sort.Strings` + `strings.Join` (allocates a new string) on every `ComputeMaterialHash`. The empty
case is guarded, but any present vector allocates a slice + a new string even when it is already in
canonical order (the common case — feeds emit spec-order vectors). This is per-write, ×2 (v3+v4).
**Impact:** Reachable every `Ingest` that has a CVSS vector (most CVEs). Two small slice+string
allocations per call. Minor in isolation; listed because it is on the same per-write hash path and is
cheap to gate.
**Confidence:** Strong-static.
**Effort:** Localized. Cheapest correct fix: check `sort.StringsAreSorted(metrics)` before allocating
the joined result and return the original string when already sorted — avoids the `Join` allocation in
the common already-canonical case. (The `Split` still allocates; a fully alloc-free scan is possible
but readability-negative for the gain — note as optional.)
**Verification plan:** `-benchmem` on `ComputeMaterialHash` with an already-sorted vector. **Correctness
guard:** `hash_test.go` vector-permutation cases must still produce equal hashes for reordered metrics.

---

## Items examined and judged NOT findings

- **FTS document construction (`fts.go`, `UpsertCVESearchIndex`)** — `to_tsvector`/`setweight` run
  **server-side** in Postgres; Go only `strings.Join`s CWE IDs and package names (two small strings
  per write). `collectPackageNames` dedups with a map but n is tiny. No large Go-side FTS string is
  built and discarded — the lane brief's "FTS document string" concern does not materialize here. Not
  a finding.
- **`buildAffectedPkgKeys` / `buildCPEStrings`** (`pipeline.go:330-350`) — both correctly pre-size
  with `make([]T, 0, len(...))`. Good; no change.
- **`bytes.ReplaceAll(normalizedJSON, {0}, {})`** (`pipeline.go:50`, `:115`) — allocates only when a
  NUL is present (ReplaceAll returns a copy regardless, but the input is the just-marshaled buffer,
  already owned). Marginal; folding the NUL-strip into a streaming encoder is not worth the
  readability cost. Not a finding on its own (subsumed by the marshal round-trip finding).
- **Child-row insert loops** (`pipeline.go:193-240`) — per-row `Exec` is a data-access concern (N
  inserts), not a memory-lane concern; the parameter structs are stack-modest. Out of this lane.
- **No `sync.Pool` for hash/JCS scratch buffers** — a pool is a candidate optimization, but the right
  first move is to *eliminate* the JCS pass (finding 1) rather than pool its buffers. Pooling a
  `bytes.Buffer`/hasher would help only the residual `json.Marshal`; note as a follow-on after
  finding 1 is decided, not an independent finding.

---

## Suspected Bugs (for follow-up)

None. (Lane stayed within memory/allocation scope; no correctness anomalies observed on the read path.
The marshal→DB→unmarshal self-round-trip in findings 2 relies on `normalized_json` being a faithful
re-encoding of the current `patch`; the only divergence is the NUL strip, which is behaviorally
correct and not a bug.)
