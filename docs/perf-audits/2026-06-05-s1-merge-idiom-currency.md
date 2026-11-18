# S1 Merge & corpus write path — framework-idiom currency lane

> Lane: **idiom-currency**. Scope: superseded/slow stdlib idioms the merge write path still uses,
> and faster current Go APIs it bypasses. Project is on **Go 1.26.2** (`go.mod`); the version index
> (`version-indexes/go.md`) is `covered_through: Go 1.24`. Claims at or below 1.24 inherit the
> index's freshness (Strong-static where the code structure is certain); anything past 1.24 is
> marked Heuristic and never fabricated.
>
> Files read: `internal/merge/{hash,resolve,pipeline,fts,store,advisory}.go`,
> `internal/store/cve.go`, `internal/store/queries/cves.sql`, `internal/feed/interface.go`.
>
> The dominant cost of this slice — per-source-write recompute, DB round-trip amplification, FTS GIN
> rebuild — is architectural and is already owned by the cost-map (`2026-06-05-s1-merge-cost-map.md`)
> and the data-access lane. This lane does **not** re-litigate those. It reports only idiom-currency
> deltas: where a newer stdlib API would do the same work with fewer allocations.

---

### [MINOR] `sort.Slice` / `sort.Strings` on every material-hash and resolve pass — superseded by `slices.Sort` / `slices.SortFunc` (per-call closure + interface boxing avoided)

**Location:** `internal/merge/hash.go:57,58,59,116`; `internal/merge/resolve.go:217,331`

**Problem:** The hash and resolve paths sort with the pre-generics `sort` package. `sort.Strings`
and `sort.Slice` both route through the `sort.Interface` machinery: `sort.Slice` allocates and boxes
a closure (`func(i, j int) bool`) and a reflect-backed swapper on every call, and `sort.Strings`
sorts via the `StringSlice` interface adapter rather than a monomorphized generic. The version index
(`version-indexes/go.md` line 64, **Go 1.21 `slices` package**) states explicitly: "use
`slices.Sort`/`slices.SortFunc` instead of `sort.Slice` to avoid the per-call closure allocation."
`slices.Sort[[]string]` is a compiler-monomorphized sort with no interface dispatch and no closure;
`slices.SortFunc` takes a `cmp`-style comparator without the index-indirection swapper.

Concretely:
- `hash.go:57` `sort.Strings(f.CWEIDs)` → `slices.Sort(f.CWEIDs)`
- `hash.go:58` `sort.Strings(f.AffectedCPEs)` → `slices.Sort(f.AffectedCPEs)`
- `hash.go:116` `sort.Strings(metrics)` → `slices.Sort(metrics)`
- `resolve.go:217` `sort.Strings(r.CWEIDs)` → `slices.Sort(r.CWEIDs)`
- `resolve.go:331` `sort.Strings(others)` → `slices.Sort(others)`
- `hash.go:59` `sort.Slice(f.AffectedPkgs, func(i,j int) bool {…})` → `slices.SortFunc(f.AffectedPkgs, func(a, b affectedPkgKey) int {…})` (drops the per-call closure-boxing of `sort.Slice` and the reflect swapper; the comparator becomes a value-typed `cmp.Compare`-style func)

`resolve.go` already imports `slices` (used at lines 142/156/239 via `slices.Concat`), so for that
file the change adds no import. `hash.go` would swap its `sort` import for `slices`.

**Impact:** Reachability: the material-hash path runs **unconditionally on every `Ingest`**
(`pipeline.go:136`), and `resolve()` runs once per `Ingest` as well — the cost-map establishes
`Ingest` is invoked on the order of 10^6 times for a full multi-source corpus sync. So these six
sort sites execute on that same 10^6 multiplier. Per-occurrence: each `sort.Slice` call is one
closure heap-allocation + interface-backed swap path; `sort.Strings` is interface dispatch per
comparison. The slices are small per CVE (bounded n: CWEs, CPEs, metric segments, package keys), so
the **per-call** win is a constant-factor allocation/dispatch reduction, not a complexity change —
this is why it ranks MINOR, not higher. The aggregate is the constant factor × 10^6 invocations ×
6 call sites, landing on the GC as avoidable short-lived closure allocations. Note the same arrays
are sorted twice per CVE (once in `resolve`, once again in `ComputeMaterialHash`) so each invocation
hits several of these sites.

**Confidence:** Strong-static — the API substitution is mechanical and the index explicitly names
`sort.Slice` closure allocation as the thing `slices.Sort`/`SortFunc` removes (index line 64, Go
1.21, ≤ covered_through). The *magnitude* of the win is Heuristic (no profiler here) but the
*direction* is certain.

**Effort:** Localized — two files, no signature or cross-package change; `resolve.go` needs no new
import.

**Verification plan:** Allocation argument — `go build -gcflags='-m'` on `hash.go` will show the
`sort.Slice` comparator closure escaping to the heap at line 59; after switching to
`slices.SortFunc` the comparator is a value passed to a generic and the escape line disappears. A
`go test -bench -benchmem` on `ComputeMaterialHash` over a representative `MaterialFields` (CWEs +
CPEs + several packages) pins the allocs/op delta. Correctness guard: the existing
`hash_test.go` (order-independence of the hash) and `resolve_test.go` must stay green —
`slices.Sort` is a total order over `string` identical to `sort.Strings`, and the `SortFunc`
comparator must reproduce the exact `(Ecosystem, PackageName, Introduced)` tiebreak at hash.go:60-67
so the canonical byte output (and therefore every stored `material_hash`) is byte-identical. The
hash golden tests are the pin that proves no behavior change.

---

### [MINOR] CWE-union map→slice→`sort.Strings` materialization in `resolve` — candidate for `slices.Sorted(maps.Keys(...))` (Go 1.23), but bounded-n and marginal

**Location:** `internal/merge/resolve.go:205-217` (CWE set), and the analogous `otherSources`
key-collection at `resolve.go:320-333`

**Problem:** The CWE union builds a `map[string]struct{}`, then manually `append`s every key into a
pre-sized slice, then `sort.Strings`. The version index records two newer idioms that collapse this:
`maps.Keys` (Go 1.23 iterator, index line 67) and `slices.Sorted` (Go 1.23, index line 65), so
`r.CWEIDs = slices.Sorted(maps.Keys(cweSet))` replaces the append-loop **and** the sort in one call,
without the intermediate manual `append` loop. Same shape applies to `otherSources` (collect keys →
`sort.Strings`).

**Impact:** Reachability is the per-`Ingest` 10^6 multiplier again, but this is primarily a
readability/idiom consolidation: `slices.Sorted(maps.Keys(...))` still allocates the result slice
and still sorts, so the only saved work is the explicit `make`+`append` loop being folded into the
collector — a marginal allocation/branch reduction over a **bounded, small** key set (a CVE has a
handful of distinct CWE IDs and a handful of "other" sources). Under the lane calibration ("theoretical
big-O improvements on a provably bounded, small n" are NOT findings), the perf component here is
negligible; I record it only as an idiom-currency note, not a perf win to chase.

**Confidence:** Heuristic — the API exists and is index-cited (≤ covered_through), but the
performance benefit is below the calibration floor for this bounded n. Flagged for manual decision,
not asserted as a win.

**Effort:** Localized.

**Verification plan:** N/A as a perf change (bounded n). If adopted purely for idiom currency, the
correctness guard is `resolve_test.go`'s assertions on `CWEIDs` ordering and dedup, which must stay
green; `slices.Sorted(maps.Keys(m))` yields the identical sorted, deduped key set.

---

## Items examined and explicitly NOT flagged (to prevent re-litigation)

- **`crypto/sha256` buffered vs streaming hash over the JCS writer** (hash.go:81-94). The candidate
  was: stream `sha256` over a writer rather than `sha256.Sum256(jcs)` on a fully-buffered `[]byte`.
  Rejected as out-of-lane: the canonicalizer in use
  (`cyberphone/json-canonicalization` `jsoncanonicalizer.Transform`) exposes **only**
  `Transform([]byte) ([]byte, error)` — it returns a materialized byte slice, so the JCS output is
  already buffered before the hash sees it. Streaming the hash would save nothing unless the
  *canonicalizer* were replaced with a streaming one, which is a third-party-dependency change, not a
  stdlib idiom-currency item. The cost-map already notes the double-buffer (marshal → Transform) as a
  CPU micro-line; not my lane.

- **`encoding/json` Marshal for canonicalization** (hash.go:81, pipeline.go:45). The code marshals to
  JSON and then re-parses/re-emits via JCS `Transform`. Replacing `encoding/json` with a streaming or
  canonical-JSON emitter is a serialization-stack/dependency decision, not a "newer stdlib API the
  code bypasses" — the index names no stdlib canonical-JSON facility. Out of lane; recorded in the
  cost-map as a structural note.

- **pgx batch / `CopyFrom` APIs.** The merge write path runs through `database/sql` (`merge.Store` =
  `DB() *sql.DB`, `store.go:9-11`; `pipeline.go` uses `BeginTx`/`ExecContext`/sqlc-over-`*sql.Tx`),
  **not** the pgx-native interface, so `pgx.Batch`/`pgxpool` batch APIs are not reachable from here
  without an architectural change. The per-`Ingest` round-trip count (advisory lock → upsert source →
  GetAllCVESources → upsert cve → 3× child DELETE → per-row child INSERT → EPSS → FTS) is exactly the
  data-access lane's territory and is owned by the cost-map. Pipelining those into a `pgx.Batch` is a
  cross-package data-access redesign, not an idiom-currency swap. Out of lane.

- **`strings.Join` for FTS document assembly** (`fts.go:7`, `pipeline.go:287-288`). `strings.Join`
  into a SQL parameter is the correct, allocation-minimal idiom here; the tsvector is built
  server-side by `to_tsvector` (cves.sql:110-122). No `+=`-in-loop or `bytes.Buffer` misuse exists to
  modernize. Nothing to flag.

- **`bytes.ReplaceAll` null-byte stripping** (pipeline.go:50,115). Correct and current; no superseding
  API.

- **`hash/fnv` advisory key** (advisory.go:23-31). `fnv.New64a` is the right tool for a stable lock
  key; `maphash.Comparable` (index line 80, Go 1.24) is for in-process map keys, not a *stable*
  cross-process value, so it would be wrong here. Correctly NOT a finding.

---

## Suspected Bugs (for follow-up)

None observed in this idiom-currency pass. (The cost-map already noted that `buildAffectedPkgKeys`
omits `LastAffected` from the material hash; that is intentional per the §5.3 "minimal key"
comment and is not an idiom-currency concern.)
