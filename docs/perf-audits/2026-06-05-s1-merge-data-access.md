# S1 — Merge & corpus write path — data-access & I/O lane

ABOUTME: Performance audit of the merge pipeline's DB round-trip and I/O behavior during bulk feed ingest.
ABOUTME: Lane = data-access; scope = internal/merge/**, internal/store/cve.go, adjacent SQL/DDL.

**Auditor lane:** data-access & I/O. **Date:** 2026-06-05. **Runtime profiling:** unavailable
(no Docker/testcontainers) — all confidence is `Strong-static` or `Heuristic`, never `Measured`.

## Scope examined

- `internal/merge/pipeline.go` (the `Ingest` entry point, child-table delete/re-insert, PK migration)
- `internal/merge/advisory.go`, `store.go`, `fts.go`
- `internal/ingest/handler.go` (the loop that calls `merge.Ingest` once per patch)
- `internal/store/cve.go` (read path; `GetCVEMaterialHash`)
- `internal/store/queries/cves.sql`, `internal/store/queries/vendor_enrichment.sql`
- DDL: `migrations/000002_create_cve_core.up.sql`, `000029_vendor_enrichment.up.sql`, `000026_retention_indexes.up.sql`
- DB wiring: `internal/store/store.go`, `cmd/cvert-ops/main.go` (pool / exec-mode)

## Hot-path model

`internal/ingest/handler.go:163-211` loops over every patch in every page and calls
`mergeFn(ctx, mergeSt, patch, source)` (= `merge.Ingest`) **once per source row**. There is no batch
boundary: one patch = one `BeginTx … Commit` transaction. For a ~250k-CVE feed (NVD/MITRE/OSV), the
loop body runs ~2.5 × 10⁵ times, and the per-source round-trip cost is the multiplier on the whole
ingest wall-clock.

Two structural amplifiers established from the code, both raising the cost of **every** statement
below:

1. The merge runs over `*sql.DB` obtained from `s.DB()` (`store.go:42`, `Store` interface in
   `merge/store.go`), which is `stdlib.OpenDBFromPool(pool)` (`store.go:29`). Every
   `q.X(ctx,…)` is an independent `database/sql` Exec → one network round-trip; none are pipelined.
2. The pool is configured `DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol`
   (`main.go:682`, `:741`) for PgBouncer compatibility. Simple protocol disables pgx's prepared-
   statement cache, so each statement is re-parsed/re-planned server-side on every execution — there
   is no plan reuse across the 250k iterations.

Counting the sequential statements inside one `Ingest` for a typical NVD patch (no PK migration; has
references + CPEs; raw payload present):

| # | Statement | pipeline.go |
|---|---|---|
| 1 | `BeginTx` | :52 |
| 2 | `pg_advisory_xact_lock` | :60 |
| 3 | `UpsertCVESource` | :102 |
| 4 | `InsertCVERawPayload` | :116 |
| 5 | `GetAllCVESources` | :126 |
| 6 | `UpsertCVE` | :158 |
| 7 | `DeleteCVEReferences` + **N**× `InsertCVEReference` | :190-205 |
| 8 | `DeleteCVEAffectedPackages` + **M**× `InsertAffectedPackage` | :209-226 |
| 9 | `DeleteCVEAffectedCPEs` + **K**× `InsertAffectedCPE` | :229-240 |
| 10 | `GetEPSSStaging` | :262 |
| 11 | `UpdateCVEEPSS` (conditional) | :269 |
| 12 | `DeleteEPSSStaging` | :277 |
| 13 | `UpsertCVESearchIndex` | :284 |
| 14 | `Commit` | :293 |

**Fixed cost ≈ 12–13 round-trips per source row, plus N+M+K per-child-row inserts**, all
sequential. NVD CPE lists routinely run to dozens or hundreds of `cpeMatch` entries, so K dominates.
Plus the ingest loop adds **2 more** round-trips per patch *outside* the transaction (pre- and
post-merge `GetCVEMaterialHash`, `handler.go:169` and `:194`) when realtime alerts are enabled.

So: per ingested source row ≈ **(14 fixed + N + M + K) round-trips**, × 10⁵–10⁶ rows per full feed.
The findings below attack that multiplier.

---

## Findings

### CRITICAL — Per-child-row INSERT loops (references / packages / CPEs) instead of one multi-row INSERT
**Location:** `internal/merge/pipeline.go:193-206, 212-226, 232-240`; queries `cves.sql:93-108`
**Problem:** Each child table is rebuilt with a single `DELETE` followed by a Go `for` loop that
issues **one `InsertCVEReference` / `InsertAffectedPackage` / `InsertAffectedCPE` per row**. This is
the textbook N+1 write: K CPE rows = K sequential round-trips. NVD CVEs commonly carry tens-to-
hundreds of CPE matches and many references, so for the worst CVEs the CPE loop alone is the largest
single contributor to that CVE's ingest time. Because the statements run over the stdlib `*sql.DB`
adapter under simple protocol, each insert also pays a fresh server-side parse/plan.
**Impact:** Reachable on every source write that has children (the common case). Per-occurrence:
`O(N+M+K)` round-trips where a single multi-row `INSERT … VALUES (…),(…),…` (or `unnest($1,$2,$3)`)
is `O(1)`. Aggregate: across a 250k feed with an average of, say, a few CPEs/refs each, this is the
dominant write-amplifier — easily the majority of total ingest round-trips. Collapsing each loop to
one statement removes (N-1)+(M-1)+(K-1) round-trips per CVE.
**Confidence:** Strong-static (the loop structure and one-row VALUES are right there).
**Effort:** Contained — add multi-row insert queries (sqlc supports `unnest`-based bulk insert, or
hand-build with squirrel which merge already depends on transitively); the `ON CONFLICT DO NOTHING`
dedup semantics carry over to a multi-row VALUES list unchanged.
**Verification plan:** Count statements emitted per `Ingest` before/after for a fixture CVE with K
CPEs (the existing `pipeline_integration_test.go` can assert via a statement-counting wrapper or
`pg_stat_statements`). Correctness guard: the integration test asserting the resulting child rows
(content + dedup) must stay green; the multi-row insert must preserve `ON CONFLICT (cve_id,
url_canonical)/(cve_id, cpe_normalized) DO NOTHING`.

### CRITICAL — 12+ sequential round-trips per source row not pipelined; merge bypasses pgx.Batch
**Location:** `internal/merge/pipeline.go:38-293`; store wiring `internal/store/store.go:29,42`;
`internal/merge/store.go:9-11`
**Problem:** The whole `Ingest` body is a strictly sequential chain of ~12 fixed single-statement
round-trips (table above) over `*sql.DB`. The advisory lock, the source upsert, the raw-payload
insert, the sources re-read, the canonical upsert, the three EPSS statements, and the FTS upsert are
each their own network round-trip with no overlap. The store already exposes a pgx-native pool
(`Store.Pool()`, documented at `store.go:37-39` as *"for callers that need pgx native operations
(e.g., merge pipeline advisory locks…)"*), so the infrastructure to send these as one `pgx.Batch`
(single round-trip, pipelined) exists and is already sanctioned — but the `Store` interface the merge
depends on (`merge/store.go`) only surfaces `DB() *sql.DB`, forcing the slow path. Simple-protocol
exec mode (`main.go:682`) compounds this: no statement caching, so every one of these is re-parsed
each of the 250k iterations.
**Impact:** Reachable on every source write. ~12 round-trips → 1 batched round-trip is roughly an
order-of-magnitude reduction in fixed per-row network latency, the part that does not shrink with
better indexing. Over 10⁵–10⁶ rows per feed this is the largest fixed-cost lever after the child-row
loops. (Note: the `GetAllCVESources` → `resolve()` → `UpsertCVE` chain has a true data dependency and
cannot be in the same batch, but steps 2-4 before it and steps 7-13 after the resolve can each batch.)
**Confidence:** Heuristic on the exact speedup (no runtime), Strong-static that the round-trips are
sequential and a batched alternative is architecturally available.
**Effort:** Cross-cutting — widen the `merge.Store` interface to expose the pool (or a `pgx.Tx`), and
restructure `Ingest` into batched phases around the one unavoidable read-modify-write dependency.
Touches merge + its store interface + tests. Worth gating behind the measurement in the fix plan.
**Verification plan:** Statement/round-trip count per `Ingest` before vs after via a counting wrapper
or `pg_stat_statements.calls`. Correctness guard: full `pipeline_integration_test.go` suite,
especially the advisory-lock serialization and EPSS-staging-drain assertions, must remain green — the
advisory lock must still be the first statement of the transaction.

### MAJOR — `InsertCVERawPayload` appends a new TOAST'd JSONB row on every ingest with no dedup or guard
**Location:** `internal/merge/pipeline.go:114-123`; query `cves.sql:89-91`; DDL
`migrations/000002_create_cve_core.up.sql:107-124`
**Problem:** Step 3 does an unconditional `INSERT` into `cve_raw_payloads` for every patch that has a
`RawPayload` (NVD/MITRE/OSV always do). Unlike `cve_sources` (which has an `IS DISTINCT FROM` guard,
`cves.sql:67`) there is **no change-detection guard** — re-ingesting an unchanged CVE still writes a
full duplicate raw payload row. Raw feed payloads are large (whole NVD CVE JSON), so each is TOAST-
compressed and stored out-of-line: a write-heavy, I/O-heavy insert performed unconditionally on every
source row, including no-op re-syncs. The table is insert-only and pruned by a retention job
(`:115-120`), so this is pure write + WAL + TOAST + later-vacuum cost with no read-path benefit on
unchanged re-ingests.
**Impact:** Reachable on every source write with a raw payload (the common case). On steady-state
re-syncs — where most CVEs are unchanged — this is the single most expensive *wasted* write per row
(large TOAST insert + WAL). Across a 250k re-sync that's 250k redundant large-row inserts. Per-
occurrence cost is high (out-of-line TOAST write) even though it's "only" one round-trip.
**Confidence:** Strong-static (unconditional insert, no guard, large payload).
**Effort:** Localized — gate the insert on the source actually changing. The information is already
available: the `cve_sources` upsert at step 2 uses `IS DISTINCT FROM`; capture whether it changed
(e.g. `… RETURNING` / `RowsAffected`) and skip the raw-payload insert when the normalized source did
not change. (Coordinate with any retention/audit requirement that wants a payload per *distinct*
version, not per *fetch*.)
**Verification plan:** Assert row count of `cve_raw_payloads` is unchanged after re-ingesting an
identical patch (new integration assertion). Correctness guard: a *changed* payload still inserts a
new row; existing retention tests still pass.

### MAJOR — Two extra `GetCVEMaterialHash` round-trips per patch in the realtime ingest loop
**Location:** `internal/ingest/handler.go:167-179` (pre-merge) and `:193-201` (post-merge);
`internal/store/cve.go:32-44`
**Problem:** When realtime alert evaluation is enabled, the loop reads `material_hash` **before** the
merge and **again after** the merge, each a separate `SELECT material_hash FROM cves WHERE cve_id=$1`
round-trip *outside* the merge transaction — purely to detect whether the hash changed. But the merge
itself already computes the new `material_hash` (`pipeline.go:136-148`) and the `UpsertCVE` SQL
already knows the old vs new hash (`cves.sql:21-25` `IS DISTINCT FROM` in the `CASE`). The change
signal exists inside the transaction; the handler re-derives it with two additional full round-trips
per patch.
**Impact:** Reachable on every patch in the alert-enabled ingest path (the production `serve`
configuration). +2 round-trips per source row × 10⁵–10⁶ = a 15-20% bump on the fixed per-row
round-trip count, for information the merge already has. The pre-merge read also races the merge it's
trying to observe (a correctness smell — recorded below, not chased).
**Confidence:** Strong-static (two explicit `GetCVEMaterialHash` calls bracketing the merge).
**Effort:** Contained — have `merge.Ingest` return whether `material_hash` changed (it computes both
sides), and drive `EvaluateRealtime` off that return value; delete both handler reads.
**Verification plan:** Assert two fewer `SELECT material_hash` statements per patch via statement
counting. Correctness guard: existing realtime-eval tests asserting that `EvaluateRealtime` fires
exactly when the hash changes (and not otherwise) must stay green.

### MINOR — `GetAllCVESources` re-reads full `normalized_json` JSONB for every source on every write
**Location:** `internal/merge/pipeline.go:126`; query `cves.sql:69-70` (`SELECT *`); DDL
`migrations/000002_create_cve_core.up.sql:77-91`
**Problem:** Step 4 `GetAllCVESources` does `SELECT * FROM cve_sources WHERE cve_id=$1` — it pulls
the full `normalized_json jsonb` (potentially large/TOAST'd) for **every** source of the CVE on
**every** source write, because `resolve()` needs all sources to recompute the canonical row. That is
inherent to the per-source-write re-resolve design (§5.1), so the *read* itself is required — but
`SELECT *` also drags `source_url`, `ingested_at`, etc. that `resolve()` may not need, widening the
row and any TOAST detoast. With 8 feeds, this is up to 8 large JSONB blobs detoasted per write.
**Impact:** Reachable on every source write; cost scales with number of sources × payload size. This
is a real but bounded over-fetch (n ≤ 8 sources); flagged as MINOR because the bulk of the cost
(reading the JSONB that `resolve` genuinely needs) is inherent, and only the surplus columns are
avoidable. Worth narrowing the projection to exactly what `resolve()` consumes.
**Confidence:** Heuristic (depends on what `resolve()` actually reads — `resolve.go` consumes the
normalized JSON, so the JSONB is needed; the surplus scalar columns are the avoidable part).
**Effort:** Localized — a projected `GetAllCVESourcesForResolve` selecting only the columns
`resolve()` uses.
**Verification plan:** Diff selected columns against `resolve()`'s field access. Correctness guard:
`resolve_test.go` must stay green with the narrowed projection.

---

## Index / query-shape check (no missing-index findings on the write path)

Lookups the merge performs by key are all covered by existing indexes — verified against
`migrations/000002_create_cve_core.up.sql`:

- `GetAllCVESources` / `UpsertCVESource` / source deletes filter on `cve_id` → covered by
  `cve_sources` PK `(cve_id, source_name)` (`:90`) and child-table `*_cve_id_idx` indexes
  (`:140,165,184`).
- `FindCVEBySourceID` (`cves.sql:72-75`) filters `source_name = $1 AND source_id = $2` → served by
  `cve_sources_source_id_idx` (`:97-98`); `source_name` is the leading PK column but this predicate
  leads with `source_name` equality too, so it's sargable.
- `UpsertCVE` / `UpdateCVEEPSS` / `TombstoneCVE` / FTS upsert / EPSS staging all key on the PK.
- The `IS DISTINCT FROM` guards on `UpsertCVE` (`cves.sql:21-25`), `UpsertCVESource` (`:67`),
  `UpsertCVESearchIndex` (`:120-122`), and `UpsertVendorEnrichment` (`vendor_enrichment.sql:13-15`)
  correctly suppress dead-tuple churn and — for the FTS GIN — suppress the GIN rewrite when the
  tsvector is unchanged. **This is the right pattern and is the architecturally-intended defense
  against the GIN write-amplification the task flagged.** No finding there; the guard is present and
  correct. (The residual cost is only that the FTS upsert is still one un-batched round-trip per
  write even when it no-ops — folded into the batching finding above, not separate.)

The redundant-write concern the task raised ("FTS GIN rebuilt on every timestamp/score change") is
**already mitigated** by `cve_search_index.fts_document IS DISTINCT FROM EXCLUDED.fts_document`
(`cves.sql:122`): timestamp/score-only changes don't alter the tsvector, so the GIN is not rewritten.
Good. No finding.

## Suspected Bugs (for follow-up) — recorded, not chased

- **Pre-merge hash read races the merge it observes** (`handler.go:167-179`). The pre-merge
  `GetCVEMaterialHash` runs in autocommit *outside* the merge transaction; under concurrent ingest
  for the same CVE the "before" hash it captures may already reflect another writer's commit, so the
  before/after comparison driving `EvaluateRealtime` can miss or spuriously fire an evaluation. The
  merge's own advisory lock serializes the *writes* but not this external read. Flagged for the
  correctness lane / a bug-hunt; the performance angle (eliminating the two reads) is covered above
  and would also remove this race as a side effect.
- **`migrateCVEPKRename` / `migrateCVEPKMerge` issue ~8-9 sequential single-table UPDATE/DELETE
  statements** (`pipeline.go:399-417`, `:439-457`) on the late-binding PK-migration path. This path
  is rare (only when an alias promotes a native ID to a CVE ID), so it is **not** a hot-path finding
  and is correctly excluded per calibration — noting it only so a future reader knows it was
  considered and deliberately not ranked.
