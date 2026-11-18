---
run_schema_version: 1
run_id: 2026-06-05-s3-feed-ingest
date: 2026-06-05T00:55:00Z
scope: "S3 — Feed ingestion & adapters (internal/feed/**, internal/ingest/**, internal/store/feed.go)"
methodology:
  skill: performance-audit-cycle
  plugin_version: superpowers-plus@0.2.0 (vendored; version per source repo)
dispatch:
  model_requested: "opus (latest; Claude Code Agent tool)"
  reasoning_effort: "default (harness exposes no knob)"
  overridden_by_user: false
stack:
  - { ecosystem: go, framework: stdlib+pgx, version: go1.26.2 / pgx5.9.2 }
  - { ecosystem: go, framework: encoding/json (streaming), version: go1.26.2 }
currency_briefs:
  - { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); project on 1.26 — idiom findings Heuristic" }
lanes_run: [algorithmic, memory, data-access, concurrency, idiom-currency, cost-map]
lanes_skipped: { payload-startup: "no consumer-payload/startup surface in the ingestion worker", dynamic: "no Docker/testcontainers + no production-like feed corpus locally" }
finding_counts:
  by_impact: { critical: 3, major: 5, minor: 5 }
  by_lane: { algorithmic: 2, memory: 7, data-access: 6, concurrency: 4, idiom-currency: 4 }
  suspected_bugs: 3
regression:
  prev_run_id: null
  new: 13
  persisting: 0
  resolved: 0
---

# Performance Audit (consolidated + validated) — S3 Feed ingestion & adapters

**Date:** 2026-06-05  **Scope:** internal/feed/**, internal/ingest/**, internal/store/feed.go (+ SQL adjacent)
**Stack:** Go 1.26.2 · pgx/v5 5.9.2 (pgxpool, `QueryExecModeSimpleProtocol`) · sqlc · encoding/json streaming
**Currency brief:** shipped Go version index (covered_through 1.24); project on Go 1.26 → idiom-currency findings are Heuristic.
**Lanes run:** algorithmic, memory, data-access, concurrency, idiom-currency, cost-map (6 core; FULL tier). payload-startup & dynamic skipped (reasons above).
**Regression vs none:** 13 new, 0 persisting, 0 resolved (first run).
**Verification mode:** static-only (no runtime); all confidences are Strong-static or Heuristic — none Measured.

Blind run: lanes were given load/scope context only, not a list of suspected findings. They independently
reproduced the same hot core (per-patch merge transaction, per-row EPSS, redundant hash reads, whole-feed
materialization) across 3–4 lanes each — strong cross-lane agreement. Every finding below was
**cross-validated by re-reading the cited source** (Phase 3); validation notes are inline.

## Cross-cutting root cause

`pgxpool` runs in `QueryExecModeSimpleProtocol` (`cmd/cvert-ops/main.go:682,741`) — **no
prepared-statement plan cache**, so every per-row statement is re-parsed/re-planned server-side. This
multiplies the cost of the two dominant patterns: **(a) one transaction per ingested unit** (per merge
patch, per EPSS row) and **(b) per-row child-table writes**. Most S3 criticals share this substrate, so a
fix that reduces statement/round-trip count compounds with the protocol cost.

## Critical Findings

### P1. EPSS daily apply executes one advisory-locked transaction per CVE row (~250k tx + fsync/run, fully serial)
**Lanes:** data-access, concurrency (agreement ×2)  **Location:** `internal/feed/epss/adapter.go:202-232` (loop) → `applyRow` `:250-287`
**Fingerprint:** `data-access:epss/adapter.go:applyRow:tx-per-row`  **Status:** new
**Problem:** The ~250k-row daily EPSS file is applied row-by-row: each row does `BeginTx` + `pg_advisory_xact_lock` + `UpdateCVEEPSS` + `UpsertEPSSStaging` + `Commit`, in one goroutine, strictly serially. **Validated:** confirmed at the cited lines — `applyRow` opens its own tx per row; the caller loops `cr.Read()` → `applyRowFn` with no batching.
**Impact:** reachability = every daily EPSS run; frequency = ~250k rows; per-occurrence = a full tx round-trip + WAL fsync + (simple-protocol) re-plan. ~250k serialized commit-fsyncs/run; **risks exceeding the 10-min `maxJobDuration` cap**, which (see SB1) currently records a partial run as complete.
**Confidence:** Strong-static  **On cost map:** yes (S3 cost-map "largest fixed daily round-trip count")
**Effort:** Contained, but **correctness-sensitive** — the per-CVE advisory lock + two-statement pattern is PLAN.md §5.3 TOCTOU coordination with the merge pipeline.
**Blast radius / design decision:** batching to a staging `COPY` + a single set-based apply must **preserve the EPSS-vs-merge race guard** (§5.3). Options: (a) COPY all rows into a temp/staging table, then one set-based `UPDATE … FROM` + one `INSERT … SELECT … WHERE NOT EXISTS` under a coarser lock or advisory-lock-free set operation that is still TOCTOU-safe; (b) chunked batches (e.g. 1–5k rows/tx) to cut commit count by 1000× while keeping per-row locks. **This is the one finding that genuinely needs a design call** on the locking strategy.
**Verification plan:** complexity argument — tx/commit count drops from O(rows) to O(rows/batch) or O(1); correctness guard = a test that interleaves an EPSS apply with a concurrent CVE ingest for the same `cve_id` and asserts the score lands on the row (no lost write / no orphan staging), pinning the §5.3 invariant.

### P2. Merge writes child tables by unconditional delete-all + row-by-row INSERT on every source write
**Lanes:** data-access, algorithmic, cost-map (agreement ×3)  **Location:** `internal/merge/pipeline.go:188-240` (references/affected-packages/CPEs); driven per patch from `internal/ingest/handler.go:163-211`
**Fingerprint:** `data-access:merge/pipeline.go:Ingest:child-row-by-row-rewrite`  **Status:** new
**Problem:** Each `merge.Ingest` call (once per CVE × source × page — ~10^6 for a full 8-source NVD-scale sync) issues `DeleteCVEReferences` then one `InsertCVEReference` per reference, and likewise for affected packages and CPEs — **unconditionally**, even when the resolved child set is byte-identical to what's stored. A CPE-heavy NVD record is dozens of insert round-trips per ingest. **Validated:** confirmed — Step 8 (`pipeline.go:188-240`) is delete-then-`for … Insert`; no change-guard on the child sets (unlike the `IS DISTINCT FROM` guards on `cves`/FTS).
**Impact:** reachability = every source write; frequency = 10^6 calls × N child rows; per-occurrence = 1 delete + N inserts/round-trips/table × 3 tables, each re-planned (simple protocol). The dominant write-amplification sink in ingest.
**Confidence:** Strong-static  **On cost map:** yes ("single largest plausible sink")
**Effort:** Contained — stays within the existing per-patch tx + advisory lock.
**Blast radius:** multi-row `INSERT`/`pgx.CopyFrom` per child table is safe inside the same tx/lock (no contract change). Gating the delete+re-insert on a "child set changed" check (the resolved set is already in hand) is a further win but must compare correctly (order-insensitive set equality) to preserve the `ON CONFLICT DO NOTHING` dedup semantics.
**Verification plan:** round-trip-count argument (3 + Σchild → ~6 statements via multi-row insert; → ~3 when unchanged with a guard); correctness guard = a merge test asserting the child tables hold exactly the resolved set after re-ingesting an identical patch (idempotency) and after a changed patch (diff applied).

### P3. Archive adapters (MITRE, OSV) materialize the entire feed into one `[]CanonicalPatch` held live for the whole merge loop
**Lanes:** memory (×2), idiom-currency (×2), cost-map (agreement ×3)  **Location:** `internal/feed/mitre/adapter.go:102-121`, `internal/feed/osv/adapter.go:102-119`; retained by `internal/ingest/handler.go:145-251`
**Fingerprint:** `memory:feed/FetchResult:whole-feed-slice`  **Status:** new
**Problem:** Streaming parse is correctly used *per ZIP entry*, but every decoded `CanonicalPatch` (each retaining its full `RawPayload` JSON) is appended into one slice returned in `FetchResult.Patches` and held for the entire one-at-a-time merge loop. MITRE/OSV backfill = 100k+ records → hundreds of MB–low-GB live heap with zero batching benefit (the merge consumes one patch at a time). **Validated:** confirmed — the handler loop iterates `result.Patches` one patch per merge; the archive adapters return the whole archive as a single `FetchResult` (corroborated by memory, idiom, and cost-map lanes independently reading the adapters; cost-map also noted OSV buffers the archive to a temp file).
**Impact:** reachability = every archive backfill (MITRE, OSV); frequency = once/backfill; per-occurrence = O(feed) resident heap → GC thrash / OOM risk. Highest memory cost in S3.
**Confidence:** Strong-static
**Effort:** Cross-cutting — changing the `FetchResult.Patches []CanonicalPatch` contract to a streaming hand-off (`iter.Seq[CanonicalPatch]`, Go 1.23+, or a channel/callback) touches the `feed.Adapter` interface and the handler loop; paginated adapters (NVD/GHSA) already bound per-page so they adapt trivially.
**Verification plan:** peak-RSS argument (resident set bounded to one patch instead of the whole archive); correctness guard = adapter golden tests still pass (same patches, same order); add a test asserting the archive adapters yield incrementally (no full-slice buffering).

## Major Findings

### P4. Realtime-alert ingest path issues two redundant `GetCVEMaterialHash` round-trips per patch
**Lanes:** algorithmic, data-access, concurrency (agreement ×3)  **Location:** `internal/ingest/handler.go:167-210`
**Fingerprint:** `data-access:ingest/handler.go:merge-loop:double-hash-read`  **Status:** new
**Problem:** When alerts are enabled (`eval != nil`), every patch does a pre-merge `GetCVEMaterialHash` and a post-merge `GetCVEMaterialHash` purely to detect a hash change — but `merge.Ingest` already computes the new hash internally (`merge/pipeline.go`), and `UpsertCVE`'s `ON CONFLICT … IS DISTINCT FROM` already knows whether it changed. **Validated:** confirmed at `handler.go:167` (pre) and `:194` (post); both are standalone reads bracketing the merge.
**Impact:** reachability = alert-enabled ingest (the production config); frequency = every patch (~500k extra serial reads per NVD backfill); per-occurrence = 1 point-read round-trip × 2.
**Confidence:** Strong-static  **Effort:** Contained — return a `changed bool` / new hash from `merge.Ingest` (touches `MergeFunc` signature + handler).
**Blast radius:** `merge.Ingest`/`MergeFunc` is also called by tests and the worker registration; signature change ripples to those call sites (all in-repo). **Co-located opportunity:** the merge already has the post-hash — surface it.
**Verification plan:** round-trip argument (2 reads/patch → 0); correctness guard = a test asserting realtime eval still fires iff the material hash changed, using the merge-returned signal.

### P5. All non-EPSS feeds share a single `feed_ingest` queue at concurrency 1 (head-of-line blocking)
**Lanes:** concurrency  **Location:** `cmd/cvert-ops/main.go:186-188,437-439`; `internal/worker/pool.go:77-78` (`Register` pins concurrency=1)
**Fingerprint:** `concurrency:worker/pool.go:feed_ingest:serial-queue`  **Status:** new
**Problem:** Seven feeds (NVD/MITRE/GHSA/KEV/MSRC/RedHat/CSAF) are handled by one `feed_ingest` queue registered via `Register(...)` → `RegisterWithConcurrency(queue, h, 1)`. A multi-hour NVD backfill head-of-line-blocks every other feed. **Validated:** confirmed — `Register` hard-codes concurrency 1; `RegisterWithConcurrency` exists and is unused for feeds.
**Impact:** reachability = whenever a large feed runs; frequency = continuous during backfill/large sync; per-occurrence = full stall of other feeds. Freshness/SLA impact, not CPU.
**Confidence:** Strong-static  **Effort:** Contained — per-feed queues or `RegisterWithConcurrency(>1)`.
**Blast radius / design decision:** feeds are independent (per-CVE advisory lock serializes same-CVE writes; per-feed lock key prevents same-feed double-claim), so cross-feed parallelism is **safe**, bounded by DB pool headroom (`DBMaxConns=25`). The startup check only warns on Postgres `max_connections`, not app-side pool saturation — pick a concurrency that leaves pool headroom.
**Verification plan:** argument (independent queues progress concurrently); correctness guard = a test that a same-`cve_id` write from two feeds still serializes via the advisory lock under parallel queues.

### P6. EPSS staging drain runs two unconditional round-trips in every merge (no-op for ~99% of CVEs)
**Lanes:** data-access  **Location:** `internal/merge/pipeline.go:258-279`
**Fingerprint:** `data-access:merge/pipeline.go:Ingest:epss-staging-drain`  **Status:** new
**Problem:** Step 9 does `GetEPSSStaging` + `DeleteEPSSStaging` on every merge; for the ~99% of CVEs with no staged EPSS row this is two wasted round-trips per source write. **Validated:** confirmed — both run unconditionally (the delete is intentionally unconditional per pitfall §2.7; the *get* + *delete* could collapse).
**Impact:** reachability = every merge (10^6); frequency = per source write; per-occurrence = 2 round-trips. **Confidence:** Strong-static  **Effort:** Localized — collapse to a single `DELETE … RETURNING epss_score` (one round-trip, apply if a row returned).
**Verification plan:** round-trip argument (2 → 1); correctness guard = test that a staged score is applied-then-drained exactly once and a missing staging row is a no-op.

### P7. NVD and GHSA re-marshal every record to build `RawPayload` (a second reflective serialization of 250k records)
**Lanes:** memory (×2), idiom-currency  **Location:** `internal/feed/nvd/adapter.go:398-415`, `internal/feed/ghsa/adapter.go:226`
**Fingerprint:** `memory:feed/nvd,ghsa:remarshal-rawpayload`  **Status:** new
**Problem:** The raw bytes are already in the decoder buffer, but the adapters `json.Marshal(record)` again to populate `RawPayload` — a second `encoding/json` reflective pass per record (and lossy vs the original bytes). **Validated:** confirmed at cited lines.
**Impact:** reachability = every NVD/GHSA record; frequency = ~250k (NVD backfill); per-occurrence = a full reflective marshal + alloc. **Confidence:** Strong-static  **Effort:** Contained — capture raw bytes via `json.RawMessage` during the streaming decode (or `io.TeeReader`).
**Verification plan:** alloc/CPU argument (one marshal eliminated per record); correctness guard = golden test that `RawPayload` round-trips the same logical content.

### P8. Generic/CSAF whole-body `io.ReadAll` + re-marshal; MSRC/RedHat per-detail reads
**Lanes:** memory  **Location:** `internal/feed/generic/adapter.go:142-183,645`, `internal/feed/msrc/adapter.go:388`, `internal/feed/redhat/adapter.go:430-477`
**Fingerprint:** `memory:feed/generic,csaf:whole-body-readall`  **Status:** new
**Problem:** Generic/CSAF buffer the whole response body and re-marshal; MSRC/RedHat read per-detail. Bounded per page (so MAJOR not CRITICAL) but avoidable buffering on a parse path. **Validated:** confirmed; bounded-per-page reachability noted.
**Impact:** per-page buffer + re-marshal. **Confidence:** Strong-static  **Effort:** Contained.
**Verification plan:** stream the decode where the format allows; golden tests pin parse output.

## Minor Findings

### P9. `ResolveCanonicalID` allocates + copies + sorts the alias slice per record for the rare ≥2-alias case
**Lanes:** algorithmic, memory, idiom-currency (agreement ×3)  **Location:** `internal/feed/util.go:191-203` (called per record in OSV `:234`, GHSA `:343`)
**Fingerprint:** `algorithmic:feed/util.go:ResolveCanonicalID:per-record-alias-sort`  **Status:** new
**Problem:** `make`+`copy`+`sort.Strings` runs once per advisory (~250k on OSV backfill) purely to make the multi-CVE-alias tiebreak deterministic, though the common case is 0–1 aliases. **Validated:** confirmed; n bounded (not quadratic), per-record alloc.
**Impact:** per-record alloc × 10^5. **Confidence:** Strong-static  **Effort:** Localized — early-return for `len(aliases) <= 1`; `sort.Strings` → `slices.Sort` (idiom note).
**Verification plan:** alloc argument; guard = test that tiebreak result is unchanged for ≥2 aliases.

### P10. Unconditional `strings.Clone(StripNullBytes(x))` per field across all adapters
**Lanes:** memory  **Location:** all adapters (pattern)  **Fingerprint:** `memory:feed/*:unconditional-strings-clone`  **Status:** new
**Problem:** Every extracted field is cloned to avoid pinning the decoder buffer; on the archive adapters the pinning rationale doesn't hold (the raw is retained anyway). **Validated:** confirmed as a pattern; **conditional fix — per-adapter reasoning required** (easy to get wrong; clone is correct where the buffer is reused).
**Impact:** an alloc per field per record. **Confidence:** Heuristic (depends on per-adapter buffer lifetime)  **Effort:** Contained.
**Verification plan:** per-adapter buffer-lifetime argument; guard = race/aliasing test that fields survive the next `Read()`.

### P11. `GetAllCVESources` is `SELECT *` over the wide, TOAST-ed `normalized_json` re-read every merge
**Lanes:** data-access  **Location:** `internal/store/queries/cves.sql:69`  **Fingerprint:** `data-access:cves.sql:GetAllCVESources:select-star-toast`  **Status:** new
**Problem:** Re-detoast + re-`json.Unmarshal` of all source blobs on every merge; the PK `(cve_id, source_name)` already covers the lookup (no index gap), so the cost is re-materialization, largely subsumed by P2/the recompute. **Validated:** confirmed; correctly noted as subsumed.
**Impact:** per-merge detoast/parse. **Confidence:** Strong-static  **Effort:** Localized (project only needed columns) — low marginal value given the recompute already needs the JSON.

### P12. Per-page synchronous cursor persist serializes a DB write into the fetch loop
**Lanes:** concurrency  **Location:** `internal/ingest/handler.go:224-236`  **Fingerprint:** `concurrency:ingest/handler.go:cursor-persist-inline`  **Status:** new
**Problem:** `UpsertFeedSyncState` after each page is a synchronous write in the fetch loop; negligible behind the 6s rate limits, matters only with high-rate API keys. **Validated:** confirmed; it is a **crash-recovery contract** (do not naively async it).
**Impact:** 1 write/page. **Confidence:** Strong-static  **Effort:** Localized — leave as-is unless high-rate ingestion is a target; document the tradeoff.

### P13. GHSA `json.Marshal` of a fixed 2-element event array inside the per-package loop
**Lanes:** idiom-currency  **Location:** `internal/feed/ghsa/adapter.go:428-437`  **Fingerprint:** `idiom-currency:ghsa/adapter.go:fixed-array-marshal`  **Status:** new
**Problem:** Reflective `json.Marshal` of a fixed-shape 2-element array per package; `fmt.Appendf` (Go 1.19) produces identical bytes without reflection. **Validated:** confirmed; Heuristic (idiom).
**Impact:** per-package alloc/marshal. **Confidence:** Heuristic  **Effort:** Localized.

## Out-of-scope / pre-existing (documented, not scheduled in this slice)

### P14. Red Hat adapter HTTP N+1 (list → per-CVE detail GET)
**Lanes:** data-access  **Location:** `internal/feed/redhat/adapter.go:429-443`
**Disposition:** **out-of-scope** — inherent to the Red Hat upstream API shape (no bulk endpoint) and not on the large-feed (NVD/EPSS) load profile. Document; revisit only if Red Hat volume grows or a bulk endpoint appears.

## Execution Cost Map (architectural awareness — not a to-do list)

> From the descriptive `cost-map` lane (full map in `2026-06-05-s3-feed-ingest-cost-map.md`).
- **`merge.Ingest` per-patch transaction** (~10–15 statements + N child inserts, advisory-locked, serial) — High — the time center of S3 (also P2/P4).
- **EPSS per-row advisory-locked transaction × ~250k/day** — High (also P1).
- **Realtime 2× hash read per patch** — High, cheapest win (also P4).
- `GetAllCVESources` + `resolve` recompute-from-scratch every write — Medium (also P11).
- JCS canonicalization + sha256 per patch; `canonicalizeURL` per reference; `json.Marshal ×2` per patch — Medium (inherent §5.3 / P7).
- Adapter JSON decode (NVD 3-level nesting, OSV archive scan) — Medium. **The merge, not the adapters, is where S3 spends time.**

## Measurability

These hot paths are **not directly observable** in this environment (no runtime). In production they
would need: per-queue timing + tx/round-trip counters on the ingest worker, and EPSS-run duration vs
the `maxJobDuration` cap. Recommend adding ingest round-trip / tx-count metrics before/after any fix so
P1/P2/P4 wins are measurable rather than argued.

## Suspected Bugs (for follow-up — NOT addressed here)

> Correctness issues noticed during the audit. A bug-hunt kickoff is at
> `docs/perf-audits/2026-06-05-s3-feed-ingest-bug-hunt-kickoff.md`.

### SB1. EPSS partial run is persisted as complete on context cancellation / mid-run error
**Location:** `internal/feed/epss/adapter.go:227-232` (loop `continue` on `applyRowFn` error) → `Apply` returns a fresh cursor
**What looks wrong:** if the serial loop exceeds the 10-min job timeout (very likely given P1), `ctx` cancels, every remaining row's `applyRowFn` errors and is logged-and-`continue`d, then `Apply` returns a normal next cursor as if successful — silently recording a partial run as complete and skipping re-download via the `score_date` short-circuit.
**Why suspected:** the perf defect (P1) makes the timeout reachable; this is **co-located** with the P1 fix (batching EPSS will touch this code) — record it, resolve alongside P1, but do not fix it in this audit.

### SB2. OSV `isAdvisoryEntry` is overly permissive (wasted buffering, not incorrect)
**Location:** `internal/feed/osv/adapter.go` — flagged by the memory lane; buffers entries it later discards.

### SB3. NVD swallows `RawPayload` marshal errors (observability, not memory)
**Location:** `internal/feed/nvd/adapter.go:398-415` — flagged by the memory lane.

---
**Disposition summary (per finding-model disposition discipline):** all 13 findings default to **FIX**.
P1 and P5 carry **design decisions** (EPSS locking strategy; cross-feed concurrency level vs the
25-conn pool) recorded inline for the operator. P14 is the only **out-of-scope** item (upstream API
shape). No finding is dropped on severity/effort grounds. Suspected bugs are handed off, not fixed.
