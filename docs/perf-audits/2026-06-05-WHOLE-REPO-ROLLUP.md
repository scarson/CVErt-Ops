# Whole-Repo Performance Audit — Cross-Slice Roll-Up

ABOUTME: The repo-wide synthesis of the 10-slice + overlay performance audit — systemic themes that
ABOUTME: no single slice reveals, a prioritized cross-slice fix list, and a severity heat map.

**Date:** 2026-06-05  **Scope:** whole repository (CVErt-Ops, ~42k Go + ~9.2k Vue prod LOC)
**Inputs:** `runs.jsonl` (11 runs: S1–S10 + this) + every slice's consolidated report + overlay O1.
**Why this exists (conditionally REQUIRED):** the request was a **posture** question ("audit the whole
repo"), so the roll-up is required. It does not re-audit; it synthesizes already-committed slice reports.

## Headline

~98 unique findings (9 critical · 42 major · ~47 minor after cross-slice dedupe) across 10 slices, plus
~24 suspected bugs handed to `bug-hunt-cycle`. **They collapse into five systemic themes**, and the top
two themes account for the large majority of the critical/major findings. **This is not 98 unrelated
problems — it is ~5 architectural patterns repeated across the codebase.** Fixing the patterns (not the
instances) is the high-leverage move.

The corpus has a **genuine hot core** (merge / alert / feed-ingest / search) and a **large cold-glue
tail** (auth / SCIM / admin / infra) — exactly the shape predicted in the slice plan. The cold sweeps
honestly returned mostly confirmed-cold, but found that **SCIM provisioning and the auth request path are
the under-optimized exceptions in otherwise-cold code**.

## Systemic themes (grouped across slices — the real deliverable)

### Theme A — Per-item / per-request database transactions instead of batched or set-based operations  ⟶ dominant
The single most repeated pattern. A `withTx` / `withBypassTx` / `withOrgTx` helper does `BEGIN` +
`SET LOCAL` + **one** statement + `COMMIT`, and it is called **once per item or per request**:
- merge child-table writes row-by-row + ~12 statements/patch (S1-P2 / S3-P2) · EPSS apply one tx/row, ~250k/run (S3-P1)
- alert realtime one tx+query **per CVE × rule** (S2-P2) · fan-out one tx **per channel per matched CVE** (S5-P1)
- AI call fans out ~6 single-statement txns (S6-P2)
- auth `withBypassTx` per request — API-key path runs it **twice**, login **3–5×** (S8-P1/P2/P3)
- SCIM list/remap/provisioning N+1 (S9-P2/P3/P4) · feeds-list N+1 (S10-P2)
**Lever:** batch (multi-row `INSERT` / `pgx.CopyFrom` / `ANY($1)`), set-based writes, and one transaction
per logical operation instead of per row. Biggest aggregate win in the repo.

### Theme B — `SET LOCAL` + transaction overhead for single-statement reads, multiplied by the simple protocol
`cmd/cvert-ops/main.go:741` sets `QueryExecModeSimpleProtocol` (for PgBouncer) — **no prepared-statement
plan cache**, so every statement is re-parsed/re-planned server-side. Layered on Theme A, each per-item
transaction pays parse+plan+`BEGIN`+`SET LOCAL`+`COMMIT` for one row. Worse, many bypass reads are against
**non-RLS tables** (`users`, `mfa_*`) where the `SET LOCAL app.bypass_rls` is a no-op (S8-P1, also S5-P2,
S10 middleware). **Lever:** a direct (non-transaction) read path for bypass-safe single-row reads; revisit
whether the simple-protocol blanket is needed on the worker (vs the PgBouncer-fronted API).

### Theme C — Missing composite / keyset indexes (cheap, high-value, no code change)
- CVE list/search keyset `(date_modified_canonical, cve_id)` — single-column index only (S4-P1, **critical-ranked quick win**)
- admin `audit_log` cross-org `(created_at, id)` — seq-scan + in-memory sort (S9-P5)
- `job_queue_runnable_idx` column order vs the claim sort (S5-P10) · `ai_usage_counters` retention `(date)` (S6-P1) · org-scoped retention composites (S6-P6)
**Lever:** one `CREATE INDEX CONCURRENTLY` migration batches all of these. The cheapest high-value work in the audit.

### Theme D — Re-fetching / re-computing invariants inside hot loops
- realtime re-loads the **entire** active rule set per CVE (S2-P1) · `squirrel.ToSql` rebuilt per CVE×rule (S2-P3)
- fan-out re-queries the invariant channel list per matched CVE (S5-P1) · merge re-resolves **all** sources from scratch per write (S1-P1)
- SCIM re-fetches tier + config per provisioning call (S9-P4) · digest re-scans the corpus per due report (S6-P5)
**Lever:** hoist invariants out of the loop; cache the active-rule snapshot (with invalidation); cache rendered SQL on the compiled rule.

### Theme E — Whole-collection materialization defeating the project's streaming mandate
- archive adapters buffer the entire feed into one slice (S3-P3, critical) · alert sweep buffers the whole window (S2-P4)
- `scimListUsers` materializes all members before paginating (S9-P1) · `/cves/{id}/sources` loads all raw blobs uncapped (S4-P5)
**Lever:** streaming return contracts (`iter.Seq` / channels), push pagination + filtering into SQL.

### Theme F — Frontend (separate process boundary; independent of A–E)
Unbounded deeply-reactive admin "Load More" lists with per-row `Intl` formatting and no virtualization
(S7-P1); no Vite vendor-chunk split → framework re-downloaded every release (S7-P2); independent-fetch
waterfalls (S7-P4). The CVE table everyone worries about is fine (capped at 25 rows).

## Prioritized cross-slice fix list (quick wins first; each names what/where)

| # | Fix | Theme | Slices | Effort |
|---|---|---|---|---|
| 1 | **One migration adding the missing composite/keyset indexes** (cves keyset, audit_log, job_queue, ai_usage/retention) | C | S4,S9,S5,S6 | Localized, no code |
| 2 | **Remove the two redundant per-record `material_hash` reads** — `merge.Ingest` returns the changed signal it already computes | A,D | S3,S1 | Contained |
| 3 | **Batch merge child-table writes** (multi-row insert/CopyFrom inside the existing tx+lock) | A | S1,S3 | Contained |
| 4 | **Direct (non-tx) read path for bypass-safe single-row reads on non-RLS tables** — fixes every-request auth overhead | A,B | S8,S5,S10 | Contained |
| 5 | **Cache the active-rule snapshot + one bypass tx per CVE in realtime eval** (with rule-change invalidation) | A,D | S2 | Contained |
| 6 | **Hoist fan-out invariants + batch per-channel delivery upserts into one tx** | A,D | S5,S2 | Contained |
| 7 | **EPSS batch apply** (staging COPY + set-based apply) — **design decision: preserve §5.3 TOCTOU locking** | A | S3 | Contained (correctness-sensitive) |
| 8 | **Streaming return contract for archive adapters** (`iter.Seq`); push SCIM list pagination into SQL | E | S3,S9 | Cross-cutting |
| 9 | **Decouple/parallelize the ingest pipeline serialization** (concurrency-1 queue, one-job-per-tick, inline realtime eval) — as a set (overlay O1) | A | S3,S5,S2 | Contained |
| 10 | **SCIM N+1 batching** (list-groups, group remap per-member, provisioning tier/config) | A,D | S9 | Contained |
| 11 | **Frontend: Vite vendor split + admin-list virtualization/formatter-hoist + fetch parallelization** | F | S7 | Contained |
| 12 | **The minor tail** (idiom swaps, per-request micro-allocs, `/readyz` caching, HMAC copies, rate-limiter `RWMutex`) — group by file | A–F | all | Localized batch |

Items 1–3 are the **highest value-to-effort**; item 1 is a no-code migration.

## Severity heat map (slice × tier × impact)

```
Slice                 Tier      Crit  Maj  Min   Dominant themes
S1  merge             FULL        2    5    5    A B D E
S2  alert engine      FULL        2    5    5    A B D E
S3  feed/ingest       FULL        3    5    5    A B E
S4  search/read       FULL        1    6    6    C A E
S5  delivery          REDUCED     1    4    8    A B D
S6  reports/AI/ret     REDUCED     0    4    7    A C D
S7  frontend (Vue)    REDUCED     0    4    9    F   (separate process)
S8  auth glue         COLD        0    3    2    A B
S9  org/SCIM glue     COLD        0    5    1    A C E
S10 infra glue        COLD        0    1    5    A B
                                 ──   ──   ──
                          totals   9   42  ~47   (pre-dedupe 53; ~6 cross-slice dupes)
```
Hot core (S1–S4) carries all 9 criticals; the cold tail's findings concentrate in SCIM (S9) and the
auth request path (S8) — the rest of the glue is genuinely cold.

## `assume-hot` findings needing operator confirmation
**None outstanding.** The cross-slice frequency calibration (ingest→merge→alert→notify, per overlay O1)
was resolved by reading the actual call sites, not left `frequency-unresolved`. The only finding tagged
optimistic-by-fail-safe during dispatch (the S5 rate-limiter "every request") was **down-ranked** during
cross-validation when two lanes found the limiter is auth/SCIM-only — recorded, not shipped top-ranked.

## Suspected bugs — repo-wide (handed to `bug-hunt-cycle`, NOT fixed here)
~24 across the slices; the **security-relevant / user-facing** ones to triage first:
- **Alert sweep can silently skip matches past the 5,000 cap while advancing the cursor → missed alerts** (S2 SB1)
- **Scheduled digests ignore `watchlist_ids` → whole-corpus digests regardless of scoping** (S6 SB2)
- **EPSS partial run persisted as complete on timeout/cancel** (S3 SB1)
- **`http.TimeoutHandler` claimed in a comment but absent everywhere** — plan-compliance gap + pool-exhaustion risk (S4 P14/SB1)
- `orgRateLimiter` free burst-refill on tier change (S9 SB1)

## Measurability posture (repo-wide)
This audit was **static-only** (no Docker/testcontainers, no production corpus). Before remediation,
instrument: per-`Ingest` round-trip/tx counters, alert realtime rule-count + round-trips, `/readyz` query
rate, and a frontend `vite build --report` + Lighthouse pass. Theme A/B wins are then **measured**, not
only argued. No finding in this audit claims `Measured`.

## Verdict
The repo is **architecturally sound but pays a pervasive per-item-transaction tax** (Themes A+B), has a
**handful of missing indexes that are free to fix** (Theme C), and **re-computes invariants in its hottest
loops** (Theme D). The fix surface is small relative to the finding count because the findings are
instances of ~5 patterns. The remediation plan (`docs/plans/2026-06-05-whole-repo-perf-audit-remediation-plan.md`)
schedules them, quick wins first, with a measurement/verification gate per task.
