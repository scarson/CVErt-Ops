# S3 Feed Ingestion — Algorithmic Complexity Audit

**Slice:** S3 "Feed ingestion & adapters" (FULL depth, HOT tier)
**Lane:** algorithmic complexity & data structures
**Date:** 2026-06-05
**Scope read:** `internal/feed/util.go`, `interface.go` (shared base); `nvd`, `ghsa`, `osv`, `mitre` adapters (deep); `generic` adapter + CSAF path; `internal/ingest/handler.go`, `epss.go`; `internal/store/feed.go`. Cited others only where they diverge.

No runtime profiling available — all confidence levels are Strong-static or Heuristic, never Measured.

---

### [CRITICAL] Two synchronous per-CVE `material_hash` SELECT round-trips inside the merge loop turn realtime alert ingest into a 2N+1 query pattern over feed-sized input

**Location:** `internal/ingest/handler.go:163-211` (the `for _, patch := range result.Patches` body), backed by `internal/store/cve.go:32-44` (`GetCVEMaterialHash` — a standalone `QueryRowContext`).

**Problem:** When the handler is built via `HandlerWithAlerts`/`HandlerWithFactoryAndAlerts` (i.e. `eval != nil && hashReader != nil`), every single patch triggers **two** separate `SELECT material_hash FROM cves WHERE cve_id = $1` round-trips — one before the merge (line 169) and one after (line 194) — in addition to the merge write itself. These are individual, serialized DB queries; there is no batching, no pipelining, and no reuse of a value the merge already computed. The merge pipeline recomputes the canonical row from scratch and necessarily knows the resulting `material_hash`, yet the handler discards that knowledge and re-reads it with a fresh query.

This is a classic N+1 (here 2N+1) pattern: N patches → 2N hash SELECTs + N merge operations, each a distinct network round-trip to Postgres.

**Impact:** Reachability is the realtime alert path, which is the *intended production configuration* for incremental syncs (the CLAUDE.md "Realtime: fires on CVE upsert when `material_hash` changes" path). Frequency: on an NVD backfill the corpus is ~250k CVEs; even a routine incremental NVD/GHSA/OSV sync pushes thousands of patches per run, each costing 2 extra round-trips. Per-occurrence cost is a full DB round-trip latency (sub-ms to low-ms each, but serialized and additive). Aggregate: 2 × (patch count) extra round-trips per ingest run, dominating wall-clock when round-trip latency × 2N exceeds the merge work itself. On a 250k backfill that is ~500k avoidable serialized SELECTs. Round-trip count, not query speed, dominates here (profile-pack data-access N+1 signal).

**Confidence:** Strong-static — the loop structure and the two distinct `hashReader.GetCVEMaterialHash` calls per iteration are unambiguous in source.

**Effort:** Contained — the merge pipeline (`merge.Ingest`) would need to return whether `material_hash` changed (and/or the new hash) so the handler can drop both reads, a signature change confined to `internal/merge` + the `MergeFunc` type + this handler. The "before" read is purely to diff against the "after" read; if merge reports change directly, both reads vanish. +high-value.

**Verification plan:** Complexity argument — count DB round-trips per ingest run as a function of patch count P: current path issues 3P (2 hash reads + 1 merge) serialized round-trips; a merge that reports hash-changed reduces this to P. The reduction is exactly 2P round-trips, linear in feed size. Correctness guard: a test that ingests a fixed corpus with the alert evaluator wired and asserts (a) `EvaluateRealtime` is invoked for exactly the CVEs whose canonical `material_hash` actually changed (unchanged behavior pinned), and (b) re-ingesting the identical corpus fires zero realtime evaluations (idempotency). The existing `handler_test.go` mock-hash-reader tests already pin the fan-out semantics; extend them to assert the evaluator-call set rather than the read count.

---

### [MINOR] `ResolveCanonicalID` unconditionally allocates and sorts an alias copy for every advisory, even the dominant 0–1-alias case

**Location:** `internal/feed/util.go:191-203`, called once per record in `osv/adapter.go:234` and `ghsa/adapter.go:343`.

**Problem:** `ResolveCanonicalID` always does `make([]string, len(aliases))` + `copy` + `sort.Strings` before scanning for a CVE-shaped alias. For OSV/GHSA the alias list is almost always 0, 1, or 2 entries, so the sort's big-O is irrelevant — but the unconditional slice allocation + copy runs once per advisory across the entire feed (OSV all.zip and GHSA backfill are thousands-to-tens-of-thousands of records). The sort exists only to make the result deterministic when multiple CVE IDs are present, which is rare. For the common path (≤1 alias) both the allocation and the sort are pure overhead: a single CVE alias needs no sort, and zero aliases need neither allocation nor scan.

**Impact:** Reachability: every OSV (`parseAdvisory`) and GHSA (`parseAdvisory`) record. Frequency: 10^4 records on backfill. Per-occurrence cost: one heap slice allocation + element copy + `sort.Strings` call on a tiny n. This is bounded-n per call, so it is **not** an accidental quadratic — it is recomputation/allocation of a result that is trivial in the common case. Aggregate is a modest constant-per-record allocation count, hence MINOR, not MAJOR. (Borderline with the memory lane; flagged here under "recompute pure result / wrong work for the access pattern.")

**Confidence:** Strong-static.

**Effort:** Localized — early-return when `len(aliases) <= 1` (no copy, no sort; just inspect the single element), and only allocate+sort when 2+ aliases exist. Behavior-preserving for the deterministic-tiebreak case.

**Verification plan:** Complexity argument — current path is `O(n log n)` time + `O(n)` allocation per call regardless of n; guarded path is `O(1)` for n≤1 and unchanged for n≥2, eliminating one allocation per record for the dominant case. Correctness guard: table test pinning current outputs for {0 aliases → nativeID, 1 CVE alias → that CVE, 1 non-CVE alias → nativeID, multiple CVE aliases → lexicographically smallest}. The multi-CVE deterministic-tiebreak case must remain identical.

---

### Items examined and deliberately NOT flagged

- **NVD `cveToCanonical` dedup maps (`seen`, `cpeSeen`)** (`nvd/adapter.go:463,488`) and the MITRE equivalents (`mitre/adapter.go:287,312`) — these use `map[string]struct{}` sets for membership, the *correct* container; they are scoped per-CVE (bounded by CWEs/CPEs of one record), not feed-sized. No quadratic.
- **`parseLinkHeader` / `linkNextRe`** (`ghsa/adapter.go:242`, `generic/adapter.go:29`) — regex compiled once at package scope; `parseLinkHeader` splits a single header string per page (bounded), not per record. Fine.
- **`ParseTime` multi-layout loop** (`util.go:33-41`) — up to 6 `time.Parse` attempts per timestamp; called per record/field. Bounded constant (6), invariant of feed size; the layouts are ordered most-likely-first. Cold relative to the DB round-trips above; not a finding.
- **CSAF `csafToPatches` best-score scan** (`generic/adapter.go:597-608`) — linear single pass over one document's score entries (bounded per vuln). Correct.
- **OSV/MITRE/GHSA per-page `patches` slice grown with bare `append`** (no preallocation) — real, but that is the memory/allocation lane, not algorithmic; the access pattern (sequential append) is correct for a streaming parse.
- **EPSS per-row advisory-locked transaction** (`epss/adapter.go:227,250-287`) — one transaction + 2 statements per row × ~250k rows daily. This is `O(n)` round-trips by *deliberate design* (PLAN.md §5.3 mandates the per-row advisory lock to coordinate the TOCTOU race with the merge pipeline). It is the documented architecture, not an accidental complexity defect, so it is out of scope for this lane's "accidental quadratic / wrong container" mandate. (Whether the whole pattern could be batched is an architecture question for §5.3, not an algorithmic bug.)
- **`computeNextCursor` / cursor math** (`nvd/adapter.go:237`) — constant-time arithmetic per page. Fine.

---

## Suspected Bugs (for follow-up)

None observed within the algorithmic lane. (Correctness of alias late-binding, withdrawn-tombstone handling, and EPSS RowsAffected semantics were not in scope and were not audited for correctness.)
