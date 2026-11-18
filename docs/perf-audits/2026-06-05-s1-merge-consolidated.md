---
run_schema_version: 1
run_id: 2026-06-05-s1-merge
date: 2026-06-05T01:05:00Z
scope: "S1 — Merge & corpus write path (internal/merge/**, internal/store/cve.go)"
methodology:
  skill: performance-audit-cycle
  plugin_version: superpowers-plus@0.2.0 (vendored; version per source repo)
dispatch:
  model_requested: "opus (latest; Claude Code Agent tool)"
  reasoning_effort: "default (harness exposes no knob)"
  overridden_by_user: false
stack:
  - { ecosystem: go, framework: stdlib+pgx, version: go1.26.2 / pgx5.9.2 }
  - { ecosystem: go, framework: "cyberphone/json-canonicalization (JCS)", version: vendored }
currency_briefs:
  - { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); project on 1.26 — idiom findings Heuristic" }
lanes_run: [algorithmic, memory, data-access, concurrency, idiom-currency, cost-map]
lanes_skipped: { payload-startup: "no payload/startup surface", dynamic: "no Docker/testcontainers + no production corpus locally" }
finding_counts:
  by_impact: { critical: 2, major: 5, minor: 5 }
  by_lane: { algorithmic: 5, memory: 4, data-access: 5, concurrency: 6, idiom-currency: 2 }
  suspected_bugs: 2
regression:
  prev_run_id: null
  new: 12
  persisting: 0
  resolved: 0
---

# Performance Audit (consolidated + validated) — S1 Merge & corpus write path

**Scope:** internal/merge/**, internal/store/cve.go (+ cves.sql / DDL adjacent)
**Stack:** Go 1.26.2 · pgx/v5 (pgxpool, simple protocol) · `cyberphone/json-canonicalization`
**Lanes run:** 6 core (FULL). payload-startup & dynamic skipped. **Verification mode:** static-only.
**Regression vs none:** 12 new (first run). Blind run; every finding cross-validated against source.

**Frequency model (verified):** `internal/ingest/handler.go` calls `merge.Ingest` once per
patch = once per CVE × source × page → ~10^6 invocations for a full multi-source NVD-scale sync,
serialized on the concurrency-1 `feed_ingest` queue. Each call is **non-incremental**: own
`BeginTx`…`Commit`, a per-CVE `pg_advisory_xact_lock`, re-read + recompute from scratch, child-table
rewrite, FTS upsert. Cost is **round-trip-bound → recompute-bound → CPU-bound**, in that order
(confirmed by the cost-map lane). All under `QueryExecModeSimpleProtocol` (no plan cache).

> **Cross-slice note (dedupe in the roll-up):** because the ingest loop *drives* merge, S3's lanes
> read `merge/pipeline.go` as adjacent context and independently surfaced four of these findings
> (the child-row-by-row rewrite, the EPSS staging drain, the double hash-read, and the per-row
> transaction shape). That is **cross-lane agreement across slices**, not double work. The canonical
> owner of `internal/merge/**` is S1; shared fingerprints are marked **[also S3]** and counted once
> in the roll-up.

## Critical Findings

### P1. Merge re-resolves the canonical row from scratch on every source write (re-reads + JSON-unmarshals all sources each time)
**Lanes:** algorithmic, memory, cost-map (agreement ×3)  **Location:** `internal/merge/pipeline.go:126-133` → `internal/merge/resolve.go:84-275`
**Fingerprint:** `algorithmic:merge/resolve.go:resolve:recompute-from-scratch`  **Status:** new
**Problem:** Every `Ingest` runs `GetAllCVESources` then `resolve()`, which `json.Unmarshal`s **all** of a CVE's `normalized_json` source blobs (NVD CPE/reference arrays are the largest payloads in the system) and rebuilds the canonical row from zero — *including the source just written one step earlier*. For a CVE that accrues k sources over a sync, that's 1+2+…+k unmarshals of the heaviest payloads. **Validated:** confirmed — `resolve.go:88` unmarshals each `src.NormalizedJson`; Step 2 wrote one of those sources moments before.
**Impact:** reachability = every source write; frequency = ~10^6/sync; per-occurrence = re-detoast + N full JSON decodes + ~10 precedence/union passes. k is bounded (~8 feeds) so it is **not** an unbounded quadratic — it is heaviest-deserialization × highest-frequency, the dominant CPU/parse cost.
**Confidence:** Strong-static  **On cost map:** yes
**Effort / design decision:** **Cross-cutting** for the full fix. The "recompute from scratch on every write" is a deliberate PLAN.md §5.1 contract (per-field precedence is simplest when recomputed). Two tiers: **(a) cheap local win, schedule now** — don't re-`GetAllCVESources`/re-parse the source just written; pass the marshaled patch into `resolve` (saves one decode/write). **(b) larger redesign, needs Sam's sign-off** — incremental/dirty-field merge that avoids re-resolving unchanged sources. (b) is **deferred with a named mechanism** (it changes the per-field precedence recompute contract and its golden tests), not on severity grounds.
**Verification plan:** complexity argument (decodes/write: k→k-1 for the local win); correctness guard = merge golden test asserting identical canonical row + `material_hash` for a multi-source CVE before/after.

### P2. Each source write issues ~12 sequential un-pipelined round-trips over `database/sql`, with child tables rewritten row-by-row
**Lanes:** data-access (×2), concurrency, algorithmic, cost-map (agreement ×4)  **Location:** `internal/merge/pipeline.go:38-293` (spine); child writes `:188-240`; `internal/merge/store.go:9-11` (`Store` exposes only `DB() *sql.DB`)
**Fingerprints:** `data-access:merge/pipeline.go:Ingest:child-row-by-row-rewrite` **[also S3 P2]** · `data-access:merge/pipeline.go:Ingest:unpipelined-roundtrips`  **Status:** new
**Problem:** Per patch: advisory lock + upsert source + (optional) raw payload + read sources + upsert cve + delete+re-insert 3 child tables **one row per statement** + EPSS drain + FTS upsert + commit — ~12 fixed statements plus one round-trip per reference/package/CPE, all sequential over the stdlib `*sql.DB` adapter even though `Store.Pool()` (pgx-native, `pgx.Batch`/`CopyFrom`) is already sanctioned for merge. A CPE-rich NVD record is dozens of serial INSERT round-trips, each re-planned (simple protocol). **Validated:** confirmed — Step 8 is `Delete*` then `for … Insert*`; `Store` interface only surfaces `DB()`.
**Impact:** reachability = every source write; frequency = 10^6 × (12 + Σchild) round-trips; the dominant write-amplifier and the largest single sink (cost-map "High"). **Confidence:** Strong-static
**Effort:** Contained — multi-row `INSERT`/`pgx.CopyFrom` per child table inside the existing tx+lock; pipeline the independent statements via `pgx.Batch`. **Blast radius:** stays within the per-patch tx + advisory lock (no §5.3 change); preserve the `ON CONFLICT DO NOTHING` dedup semantics on the child sets.
**Verification plan:** round-trip count argument (12+Σchild → ~6, or ~3 when child sets unchanged with a guard); correctness guard = idempotency test (re-ingest identical patch ⇒ child tables hold exactly the resolved set).

## Major Findings

### P3. `InsertCVERawPayload` writes a duplicate TOAST-ed JSONB row on every ingest with no change guard
**Lanes:** data-access  **Location:** `internal/merge/pipeline.go:114-123`
**Fingerprint:** `data-access:merge/pipeline.go:Ingest:rawpayload-no-guard`  **Status:** new
**Problem:** Unlike Step 2's `UpsertCVESource` (which has an `IS DISTINCT FROM` guard), Step 3 writes the raw payload unconditionally whenever `patch.RawPayload != nil`. A steady-state re-sync re-writes ~250k large TOAST-ed rows that are byte-identical to what's stored — write amplification **and** unbounded table/TOAST growth if the table is append-style. **Validated:** confirmed at cited lines; no guard, no upsert-on-unchanged.
**Impact:** reachability = every ingest with a raw payload (NVD/most feeds); frequency = ~250k/sync; per-occurrence = one large TOAST write + WAL. **Confidence:** Strong-static  **Effort:** Localized — add an `IS DISTINCT FROM` / change-gate, or skip when the source row was unchanged (Step 2 already knows). **Blast radius:** confirm the raw-payload table's retention intent (audit log vs current-state) before changing write semantics.
**Verification plan:** write-count argument (per-resync writes → only-on-change); correctness guard = test that an unchanged re-ingest writes no new raw-payload row.

### P4. `material_hash` re-serializes through JCS (a full dynamic map decode + re-emit) on every write
**Lanes:** memory  **Location:** `internal/merge/hash.go:81-94`
**Fingerprint:** `memory:merge/hash.go:ComputeMaterialHash:redundant-jcs`  **Status:** new
**Problem:** `ComputeMaterialHash` already sorts every array field, then `json.Marshal`s a fixed-field struct, then runs `jsoncanonical.Transform` — which parses that JSON into a dynamic `map[string]any`, sorts object keys, and re-emits to a second buffer. For an **internal** hash whose only consumer is its own equality check, a Go struct marshal is already deterministic, so the JCS pass is redundant work on every one of ~10^6 writes. **Validated:** confirmed — `json.Marshal(f)` then `jsoncanonical.Transform(raw)` then `sha256`.
**Impact:** reachability = every write; frequency = 10^6; per-occurrence = a full JSON re-parse + map build + re-emit + second buffer. **Confidence:** Strong-static
**Effort:** Localized — but **design decision:** dropping JCS **changes every `material_hash` value** (corpus re-hash + golden regen). Confirm `material_hash` is **not** an externally published/portable digest (cross-implementation stability is JCS's purpose) before removing it; if it must stay portable, JCS is documented overhead, not a defect — in that case the win is to canonical-emit directly instead of marshal-then-transform.
**Verification plan:** allocation/CPU argument (one parse+emit eliminated per write); correctness guard = test that the new hash is stable & order-independent across equivalent inputs (and, if kept portable, matches a JCS reference vector).

### P5. The per-CVE advisory lock is held across the entire transaction (re-read + recompute + child rewrite + FTS + commit)
**Lanes:** concurrency  **Location:** `internal/merge/pipeline.go:60` (lock) → `:293` (commit)
**Fingerprint:** `concurrency:merge/pipeline.go:Ingest:advisory-lock-whole-tx`  **Status:** new
**Problem:** `pg_advisory_xact_lock` is taken at the top and released at commit, so the child-table DELETE/INSERT storm, EPSS drain, and FTS upsert all run **inside** the lock — but the §5.3 TOCTOU race the lock exists for only needs the `{read sources → mutate cves/epss}` window serialized. On a hot CVE touched by both a feed and the EPSS evaluator, the lock-hold duration needlessly serializes them across all the extra work. **Validated:** confirmed — single `pg_advisory_xact_lock` spans the whole tx body.
**Impact:** reachability = hot CVEs with concurrent EPSS/feed writers (more reachable once P2/queue parallelism lands); frequency = per contended CVE; per-occurrence = lock-hold across ~12+N round-trips. **Confidence:** Strong-static
**Effort:** Contained — **design-sensitive:** any narrowing MUST preserve the §5.3 invariant (the read-resolve-write must stay atomic w.r.t. concurrent same-CVE writers). Likely the lock breadth is *correct as-is* and the real fix is P2 (shrink the work inside the lock), not narrowing the lock. Recorded as a design decision: **shrink the work, not the lock**, unless a proof shows the child writes are outside the race window.
**Verification plan:** argument that lock-hold time falls with P2's round-trip reduction; correctness guard = the §5.3 interleaving test (concurrent EPSS + CVE ingest for one `cve_id`).

### P6. `resolve()` rebuilds `otherSources` + concatenations ~7× per call (invariant within a resolve)
**Lanes:** algorithmic, memory (agreement ×2)  **Location:** `internal/merge/resolve.go:142,156,239,288,308` (+ `firstStr`/`firstStrPtr` `:280-316`)
**Fingerprint:** `algorithmic:merge/resolve.go:resolve:othersources-recompute`  **Status:** new
**Problem:** Each precedence-resolved field (CVSS v3/v4, packages, Status, Description, Severity ×2) recomputes the `otherSources` set (map alloc + scan + `sort.Strings`) and several `slices.Concat`, though the source set is invariant within one `resolve`. High allocation **count** (10+ maps/slices per write) even though n≤8 keeps each cheap. **Validated:** confirmed.
**Impact:** per-write alloc churn × 10^6. **Confidence:** Strong-static  **Effort:** Localized — hoist `otherSources` to one computation per priority list (≤3).
**Verification plan:** alloc-count argument; correctness guard = resolve golden test unchanged.

### P7. EPSS staging drain runs two unconditional round-trips in every merge **[also S3 P6 — merge-owned, counted here]**
**Lanes:** data-access (S1 + S3 agreement)  **Location:** `internal/merge/pipeline.go:258-279`
**Fingerprint:** `data-access:merge/pipeline.go:Ingest:epss-staging-drain`  **Status:** new
**Problem:** `GetEPSSStaging` + `DeleteEPSSStaging` on every merge; for ~99% of CVEs (no staged EPSS) these are two wasted round-trips per source write. **Validated:** confirmed; collapse to a single `DELETE … RETURNING epss_score` (apply if a row returns). **Impact:** 2 round-trips × 10^6. **Confidence:** Strong-static  **Effort:** Localized.
**Verification plan:** round-trip argument (2→1); guard = staged score applied-then-drained exactly once; missing staging = no-op.

## Minor Findings

### P8. `normalizeCVSSVector` splits+joins even when the vector is already canonical
**Lane:** memory  **Location:** `internal/merge/hash.go:106-118`  **Fingerprint:** `memory:merge/hash.go:normalizeCVSSVector:unconditional-split`  **Status:** new
Allocates a `[]string` + new string per vector ×2 per write even in the common already-sorted case. Gate with `sort.StringsAreSorted`. Strong-static, Localized.

### P9. `ComputeMaterialHash` re-sorts `CWEIDs` already sorted upstream in `resolve`
**Lane:** algorithmic  **Location:** `internal/merge/hash.go:57` vs `resolve.go:217`  **Fingerprint:** `algorithmic:merge/hash.go:duplicate-cwe-sort`  **Status:** new
Duplicate sort of the same slice every merge. Strong-static, Localized (drop one, or document the contract that the hasher owns sorting).

### P10. Six `sort.Slice`/`sort.Strings` sites on the hot path superseded by `slices.Sort`/`SortFunc`
**Lane:** idiom-currency  **Location:** `internal/merge/hash.go:57,58,59,116`; `resolve.go:217,331`  **Fingerprint:** `idiom-currency:merge/hash.go:sort-slice-to-slices`  **Status:** new
`slices.Sort`/`SortFunc` (Go 1.21, per version index) drop the `sort.Slice` closure alloc + interface dispatch. Constant-factor on a 10^6-frequency path. Heuristic (magnitude), Localized.

### P11. CWE-union `map → append-keys → sort.Strings` foldable into `slices.Sorted(maps.Keys(...))`
**Lane:** idiom-currency  **Location:** `internal/merge/resolve.go:205-217,320-333`  **Fingerprint:** `idiom-currency:merge/resolve.go:cwe-union-idiom`  **Status:** new
Go 1.23 idiom; key sets are small so the perf component is below the floor — recorded as a currency note. Heuristic, Localized.

### P12. (DEFEND) Advisory-lock-while-holding-an-open-transaction can starve the pgx pool under any future merge fan-out
**Lane:** concurrency  **Location:** design constraint across `pipeline.go:60`, `cmd/cvert-ops/main.go:750` (`DBMaxConns=25`)  **Fingerprint:** `concurrency:merge:lock-while-open-tx-pool`  **Status:** new
Not reachable today (concurrency-1), but **the guard every merge-parallelization finding must attach**: a fanned-out worker pins a pool connection for the full lock-wait; cap fan-out below `DBMaxConns` minus API headroom and dedupe by CVE ID. Strong-static, design constraint (not a standalone fix).

## Cross-slice references (counted in their owning slice — listed for the roll-up)
- **Redundant 2× `GetCVEMaterialHash` per patch on the realtime-alert path** — `internal/ingest/handler.go:167-201`; owned by **S3 P4** (`data-access:ingest/handler.go:merge-loop:double-hash-read`). S1's algorithmic, data-access, and concurrency lanes independently confirmed it (the merge already computes the post-hash — surface it via the `Ingest` return). Strong cross-slice agreement.

## Execution Cost Map (architectural awareness)
> Full map in `2026-06-05-s1-merge-cost-map.md`. Time center = per-`Ingest` DB round-trips (P2) →
recompute-from-scratch (P1) → JCS+sha256 (P4). Notably the **FTS GIN write is already protected** by
the `fts_document IS DISTINCT FROM` guard (`cves.sql:122`) — the feared GIN write-amplification does
**not** occur (data-access lane correction to the scope brief; recorded).

## Measurability
Not observable without runtime. Recommend per-`Ingest` round-trip/tx counters + resolve-decode counts
before/after P1/P2 so the wins are measured, not only argued.

## Suspected Bugs (for follow-up — NOT addressed here)
> Kickoff appended to `docs/perf-audits/2026-06-05-s3-feed-ingest-bug-hunt-kickoff.md` (shared merge/ingest scope).
- **SB1. `resolve()` silently drops a source on malformed `normalized_json`** — `internal/merge/resolve.go:90-94`: `continue` with no log/metric. A corrupt source row vanishes from the canonical merge invisibly. Co-located with P1 (the recompute fix touches this code) — record, don't fix here.
- **SB2. Pre-merge hash read races the merge** — `internal/ingest/handler.go:167`: an autocommit read *outside* the per-CVE advisory-locked tx; the change-detection compare can race a concurrent writer. Resolved as a side effect of S3 P4 (remove both reads).

---
**Disposition:** all 12 findings default to **FIX**. P1(b) (incremental-merge redesign), P4 (JCS removal),
and P5 (lock breadth) carry **design decisions** recorded inline with named mechanisms; P1(a) and the rest
schedule now. No severity/effort deferral. Suspected bugs handed off.
