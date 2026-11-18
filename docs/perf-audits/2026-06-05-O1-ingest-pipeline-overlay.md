# Overlay O1 — Ingest → Merge → Alert → Notify end-to-end pipeline cost

ABOUTME: Analysis-only overlay recovering the end-to-end cost of one CVE flowing through the
ABOUTME: ingestion pipeline — a story invisible in any single slice (S3, S1, S2, S5).

**Type:** OVERLAY (analysis-only — NOT a coverage unit; its member slices S3/S1/S2/S5 already own the
findings and the `runs.jsonl` lines). **Purpose:** the cost of ingesting *one source record* is spread
across four slices; this overlay reassembles it so the compounding is visible.

## The spine: what happens when one feed record arrives (alerts enabled, the production config)

Traced through `internal/ingest/handler.go` → `internal/merge/pipeline.go` → `internal/alert/evaluator.go`
→ `internal/notify/dispatcher.go`. Per **single source record** during a backfill (~10^6 records for a
full multi-source NVD-scale sync, serialized on the concurrency-1 `feed_ingest` queue admitting one job
per poll tick):

| Step | Slice | DB round-trips (per record) | Notes |
|---|---|---|---|
| pre-merge hash read | S3 (handler) | 1 | redundant (S3-P4) — merge computes it |
| merge: advisory lock + read all sources + recompute | S1 | ~3 + re-`Unmarshal` of **all** sources (S1-P1) | non-incremental recompute from scratch |
| merge: upsert cve + raw payload + EPSS drain | S1 | ~4 (incl. unguarded raw-payload write S1-P3, 2 staging-drain S1-P7) | |
| merge: child tables (refs/pkgs/CPEs) | S1/S3 | **1 + N per table × 3 tables** (S1-P2/S3-P2) | row-by-row delete+re-insert, unconditional |
| merge: FTS upsert + commit | S1 | ~2 | FTS guarded (no GIN write-amp) |
| post-merge hash read | S3 (handler) | 1 | redundant (S3-P4) |
| realtime alert eval | S2 | **R × (rule-set fetch + bypass tx + candidate query)** (S2-P1/P2) | re-loads ALL rules per CVE; one tx+query per rule |
| fan-out (per matched rule) | S5 | **channel-list query + snapshot + M × (per-channel bypass tx)** (S5-P1) | invariant channel list re-queried per CVE |

**Compounding:** every step runs under `QueryExecModeSimpleProtocol` (no plan cache — each statement
re-parsed/re-planned) and almost every step is its own `BEGIN`/`SET LOCAL`/`COMMIT`. A single CVE with a
handful of references/CPEs and a tenant with R active rules and M channels costs on the order of
**`~15 + Σchild + 2 + R×~3 + matches×M×4` serialized round-trips** — and the whole pipeline is **serial**
(concurrency-1 queue, one-job-per-tick admission, inline realtime eval blocking the next record's merge).

## What the overlay reveals that no single slice does

1. **The per-record transaction count is the systemic cost, and it is additive across four slices.** Each
   slice independently flagged "per-item transaction / SET LOCAL overhead" (S1-P2, S2-P2, S5-P1, plus the
   S8/S9 auth/SCIM instances on the request side). Seen end-to-end, ingesting the corpus is dominated by
   **round-trip count × the simple-protocol re-plan cost**, not by any single algorithm. The highest-
   leverage architectural lever is **reducing transactions/round-trips per record** (batch child writes,
   collapse the redundant reads, cache the rule set, hoist the channel list) — each compounds with the
   others on the same record.
2. **The pipeline is serial end-to-end at three independent choke points** that multiply: the
   concurrency-1 `feed_ingest` queue (S3-P5), the one-job-per-poll-tick admission (S5-P3), and the inline
   realtime eval blocking the merge loop (S2-P5/S3 handler). Fixing only one leaves the others as the
   ceiling — they should be addressed as a set when throughput is the goal.
3. **Two redundant reads per record (S3-P4) sit on the hottest path of all** — cheapest possible win,
   removed by having `merge.Ingest` return the changed-hash signal it already computes; this also deletes
   a TOCTOU race (SB).

## Cross-slice frequency calibration — confirmed, not assumed

The whole-repo method's fan-in calibration (ingest drives merge drives alert drives notify) was **resolved
by reading code**, not left `assume-hot`: the ingest loop calls merge once per patch (confirmed
`handler.go`), merge emits the hash-change that gates realtime eval (confirmed `evaluator.go` call site),
and alert matches drive fan-out (confirmed `dispatcher.go` call site). **No `frequency-unresolved —
assume-hot` finding remains outstanding** for the roll-up to escalate.

## Hand-off
This overlay adds **no new findings** — it re-frames S3/S1/S2/S5 findings as one compounding chain. Its
single recommendation to the remediation plan: **sequence the per-record-round-trip reductions (S3-P4,
S1-P2, S2-P1/P2, S5-P1) and the three serialization fixes (S3-P5, S5-P3, S2-P5) as a coherent "ingest
pipeline throughput" workstream**, because their wins multiply on the same hot path rather than adding.
