# Whole-Repo Performance Audit — Remediation Plan

ABOUTME: Implementation plan for the confirmed findings of the 2026-06-05 whole-repo performance audit,
ABOUTME: organized by systemic theme, quick-wins first, each task carrying a measurement/verification gate.

**Source:** `docs/perf-audits/2026-06-05-WHOLE-REPO-ROLLUP.md` + the per-slice validated reports
(`docs/perf-audits/2026-06-05-s{1..10}-*-consolidated.md`) + overlay `O1`.
**Disposition discipline (per `finding-model.md`):** every confirmed finding's default disposition is
**FIX**. This plan schedules **all** of them; nothing is deferred on severity or effort grounds. Deferred
items (the appendix) carry either a user opt-out or a named concrete mechanism. **Sam is offline** — no
opt-outs were given, so the only deferrals here name a specific mechanism (a design decision that needs
Sam's call, recorded with its mechanism).

**Per-task verification gate (mandatory, per the cycle):** every task states a **baseline** (a
measurement OR an explicit complexity/round-trip/allocation argument captured *before* the change), a
**post-change demonstration** that it improved (measurement OR argument — *if it does not improve, revert*),
and a **correctness guard** (existing tests pass + a test pinning the behavior the optimization must
preserve). **No fabricated numbers** — this environment is static-only (no Docker/testcontainers/corpus),
so baselines are round-trip/complexity arguments unless run under a real load locally. **Counter
over-optimization:** each task states the minimum change and what NOT to touch.

**Execution strategy (recommended).** Sequence by the roll-up's prioritized list: **Workstream 0 (indexes)
first** — it is no-code and de-risks everything. Then the ingest-pipeline workstream (O1) as a unit, then
the auth/SCIM transaction workstreams, then frontend, then the grouped minors. Tasks within a workstream
are mostly independent and **subagent-parallelizable**; cross-workstream ordering matters only where noted
(e.g. the `merge.Ingest` signature change in W1.T2 should land before W3 builds on it). Run the
auto-generated **bug-hunt kickoffs over the diff after each workstream** — performance changes are a
classic bug source.

> **Naming discipline (persistent-artifact rule):** task titles below are self-contained (what / where /
> why); the `[Pn]`/fingerprint suffix is traceability only. Carry this into commit messages, PR text, and
> code comments — never "fix P3" as the sole referent.

---

## Workstream 0 — Missing composite/keyset indexes (Theme C) — the no-code quick win

Single migration; run `schema-review` then `migration` skills before writing the SQL. All
`CREATE INDEX CONCURRENTLY` (outside a transaction, per golang-migrate conventions for concurrent indexes).

### T0.1 — Add the CVE list/search keyset composite index `(date_modified_canonical DESC, cve_id DESC)` [perf S4-P1]
- **What/where:** new index on `cves` matching the row-value keyset in `internal/store/cve.go:194-205` and `dsl_executor.go:142-156`.
- **Baseline:** `EXPLAIN (ANALYZE, BUFFERS)` the keyset query on a same-timestamp cluster → expect Seq/Index Scan on the leading column + a Sort node for the `cve_id` tiebreak.
- **Post-change:** the same `EXPLAIN` shows a pure Index Scan, no Sort; **if a Sort remains, revert and re-derive the index.**
- **Correctness guard:** a pagination test asserting the full keyset sequence is total-ordered with no duplicate/skipped row across page boundaries (before and after).
- **Don't touch:** the query text (it is correct); only add the index.

### T0.2 — Add the remaining missing indexes in the same migration [perf S9-P5, S5-P10, S6-P1, S6-P6]
- `audit_log (created_at DESC, id DESC)` for the cross-org admin query (S9-P5); align `job_queue_runnable_idx` to the claim `ORDER BY priority DESC, created_at` (S5-P10); add `ai_usage_counters (date)` (S6-P1); add org-scoped retention composites for `alert_events`/`notification_deliveries` (S6-P6).
- **Baseline/Post-change:** `EXPLAIN` each owning query before/after (Seq Scan+Sort → Index Scan). Revert any index that the planner doesn't adopt.
- **Correctness guard:** the owning queries return identical rows/order; the retention DELETEs delete the same set.
- **Don't touch:** retention DELETE logic, the job-claim SQL — indexes only.

---

## Workstream 1 — Ingest pipeline per-record round-trips (Themes A, B, D; overlay O1)

Treat as one coherent throughput workstream (their wins multiply on the same record).

### T1.1 — Remove the two redundant per-record `material_hash` reads by returning the changed signal from `merge.Ingest` [perf S3-P4, S1-P7-ref]
- **Where:** `internal/ingest/handler.go:167-210`; `merge.Ingest`/`MergeFunc` signature (`internal/merge/pipeline.go`, `store.go`).
- **Baseline:** 2 point-read round-trips per patch on the alert path (~500k/backfill) — round-trip argument.
- **Post-change:** 0 extra reads; realtime eval gated on the merge-returned `changed bool`/new hash. Argument: round-trips 2→0/patch.
- **Correctness guard:** test that realtime eval fires **iff** `material_hash` changed, using the merge-returned signal; also closes the TOCTOU race (SB). Existing merge/ingest tests green.
- **Don't touch:** the realtime-eval decision semantics; only the source of the change signal. Land this **before** W3 (it changes `MergeFunc`).

### T1.2 — Batch merge child-table writes (references/affected-packages/CPEs) into multi-row inserts inside the existing tx+lock [perf S1-P2, S3-P2]
- **Where:** `internal/merge/pipeline.go:188-240`.
- **Baseline:** 1 delete + N inserts per child table per patch (round-trip argument; N≈ CPE/ref count).
- **Post-change:** 1 delete + 1 multi-row insert (or `pgx.CopyFrom`) per table; optionally gate the delete+re-insert on a resolved-set-changed check. Argument: round-trips `3+Σchild → ~6` (or ~3 when unchanged).
- **Correctness guard:** idempotency test — re-ingesting an identical patch leaves child tables holding exactly the resolved set (order-insensitive); a changed patch applies the diff. Preserve `ON CONFLICT DO NOTHING` dedup.
- **Don't touch:** the per-CVE advisory lock or the tx boundary (§5.3); stay inside them.

### T1.3 — Collapse the EPSS staging drain to one `DELETE … RETURNING` [perf S1-P7] and skip the unguarded raw-payload re-write [perf S1-P3]
- **Baseline:** 2 staging round-trips + 1 unconditional raw-payload write per patch.
- **Post-change:** 1 `DELETE … RETURNING epss_score`; raw-payload written only when the source row changed (Step 2 already knows). Argument: 3→~1 round-trips/patch on the common path.
- **Correctness guard:** staged score applied-then-drained exactly once; missing staging is a no-op; raw payload still captured on change. **Confirm the raw-payload table's retention intent before changing write semantics** (audit log vs current-state).
- **Don't touch:** the staged-score application logic.

### T1.4 — EPSS daily apply: batch the per-row transactions (staging COPY + set-based apply) [perf S3-P1] — **design decision**
- **Mechanism / decision needed (Sam):** the per-CVE advisory lock + two-statement pattern is PLAN.md §5.3 TOCTOU coordination with merge. Batching to a `COPY` + set-based `UPDATE…FROM`/`INSERT…SELECT` must preserve that race guard. **Recommended:** chunked batches (1–5k rows/tx) to cut commit count ~1000× while keeping per-CVE locks, OR a staging-table set-apply under a documented locking strategy. *Because this changes a correctness-load-bearing contract, it is flagged for Sam's sign-off (see Deferred appendix) — but it IS scheduled, not dropped.*
- **Baseline:** ~250k tx + fsync/run (round-trip argument).
- **Post-change:** O(rows/batch) commits; **measure** if a local EPSS file + DB is available, else argue.
- **Correctness guard:** the §5.3 interleaving test (concurrent EPSS + CVE ingest for one `cve_id` — score lands, no lost write/orphan staging). Also fixes EPSS SB1 (partial-run-as-complete) by making the run fit the job window — but record that bug for `bug-hunt-cycle` regardless.

### T1.5 — Parallelize the ingest pipeline's three serialization choke points as a set [perf S3-P5, S5-P3, S2-P5]
- **Where:** `feed_ingest` concurrency-1 (`worker/pool.go:77`, `cmd/cvert-ops/main.go:186`); one-job-per-tick admission (`worker/pool.go:158-179`); inline realtime eval (`ingest/handler.go:192-210`).
- **Baseline:** end-to-end serial throughput (overlay O1 argument).
- **Post-change:** per-feed queues / `RegisterWithConcurrency(>1)`; batch-claim per tick; batch realtime eval **per page** (not fully async — keeps the change signal). Argument: feeds progress concurrently; queue throughput > 1/tick.
- **Correctness guard:** same-`cve_id` writes still serialize via the advisory lock under parallel queues; realtime alerts still fire for every changed CVE. **Cap fan-out below `DBMaxConns=25` minus API headroom** (the guard every parallelization finding shares).
- **Don't touch:** the advisory-lock keying.

---

## Workstream 2 — Alert realtime evaluation (Themes A, D)

### T2.1 — Cache the active-rule snapshot and use one bypass tx per CVE in realtime eval [perf S2-P1, S2-P2]
- **Baseline:** per CVE: 1 full rule-set fetch + R × (bypass tx + candidate query) (round-trip argument).
- **Post-change:** a TTL'd/change-invalidated active-rule snapshot (the cache already has an invalidation hook); evaluate the CVE against all rules in one bypass tx (or one SQL pass). Argument: per-CVE fetches → amortized; R tx → 1.
- **Correctness guard:** activating/updating a rule is visible to the next eval within the invalidation window (**security-critical** — a new rule must not be missed); match results identical to the per-rule path across multi-org fixtures.
- **Don't touch:** per-org isolation (rules carry `OrgID`); the postfilter cap.

### T2.2 — Cache rendered SQL on the compiled rule; evaluate the batch/EPSS sweep per page; parallelize the independent rule loop [perf S2-P3, S2-P4, S2-P7]
- **Baseline:** `ToSql` rebuilt per CVE×rule; whole-window buffered; rules looped serially.
- **Post-change:** render SQL once per compiled rule (vary only the bound `ANY($1)`); evaluate per page accumulating per-rule counts; bounded `errgroup`+`SetLimit` over the independent rule loop.
- **Correctness guard:** match totals identical with/without parallelism (synchronize the `totalMatches` accumulator; `SetLimit` under the pool); one run row per rule per batch preserved.

---

## Workstream 3 — Notification fan-out & delivery (Themes A, D) — depends on T1.1

### T3.1 — Hoist fan-out invariants and batch per-channel delivery upserts into one transaction [perf S5-P1, S2-P5]
- **Where:** `internal/notify/dispatcher.go:46-73`.
- **Baseline:** per matched CVE: channel-list re-query + snapshot + marshal + C × (bypass tx) (round-trip argument).
- **Post-change:** lift the invariant channel list (and constant-CVE snapshot/marshal) out of the per-CVE loop; one multi-row `INSERT … ON CONFLICT` for the C channels.
- **Correctness guard:** one delivery row per (channel, debounce window); **per-channel error isolation preserved** (per-row outcomes); idempotent upsert.

### T3.2 — Delivery/worker round-trip & connection hygiene batch [perf S5-P2, S5-P3, S5-P4, S5-P5, S5-P11, S5-P12, S6-P3, S6-P4]
- Direct read path for single-row bypass reads (S5-P2, shared with W4); batch-claim per worker tick (S5-P3); set `MaxIdleConnsPerHost` on the webhook client (S5-P4); batch the security-event writer (S5-P5); one-statement delivery claim (S5-P11); memoize per-batch lookups (S5-P12); run digest off the worker select-loop + parallelize independent reports (S6-P3, S6-P4).
- **Baseline/Post-change:** round-trip / connection-reuse / loop-blocking arguments per item.
- **Correctness guard:** delivery idempotency + per-channel isolation; security-event drop-on-overflow stays bounded (no unbounded buffer); digests still generated on schedule.

---

## Workstream 4 — Auth & SCIM per-request transactions (Themes A, B, E) — the cold-tail exceptions

### T4.1 — Direct (non-transaction) read path for bypass-safe single-row reads on non-RLS tables [perf S8-P1, S8-P2, S8-P3, S5-P2, S10-middleware]
- **Where:** `internal/store/store.go:48` (`withBypassTx`) + the hot callers (`GetUserAuthStatus`, `LookupAPIKey`+`IsUserEnabled`, the login MFA-mandate chain).
- **Baseline:** ~3–4 round-trips per bypass single-read; API-key path runs it 2×; login 3–5× (round-trip argument; 100% of authenticated requests).
- **Post-change:** a non-tx read helper for bypass-safe reads on non-RLS tables; join the API-key enabled-check into the lookup; fold the MFA-mandate predicates into one query; reuse the already-fetched `users` row for lockout state.
- **Correctness guard:** RLS-bypass semantics preserved (still cannot read org data without bypass on RLS tables); identical auth/MFA/lockout decisions incl. disabled/locked users. **Security-sensitive — review under `security-review`.**
- **Don't touch:** the RLS tables' bypass path (only non-RLS single reads get the direct path).

### T4.2 — SCIM N+1 batching: list-users pagination-in-SQL, list-groups single member query, per-member remap batch, provisioning tier/config caching [perf S9-P1, S9-P2, S9-P3, S9-P4, S9-P7]
- **Baseline:** materialize-all-members; one member query per group; ~3 tx per member on remap; 2 uncached round-trips per provisioning call (round-trip arguments).
- **Post-change:** push filter+keyset into the list-users query; one `WHERE org_id=$1` member query + in-memory map for list-groups; `BatchRecomputeSCIMRoles` (`WHERE user_id = ANY($1)`) or job-queue handoff for remap; mount `tierMiddleware` on SCIM + thread the already-fetched config.
- **Correctness guard:** SCIM responses (users/groups/$ref) byte-identical; role recomputation result unchanged; tenant tier limits still enforced.

---

## Workstream 5 — Frontend (Theme F; separate process)

### T5.1 — Bound + virtualize the admin "Load More" tables and hoist per-row formatters [perf S7-P1]
- **Baseline:** unbounded rows, deep reactivity, per-row `Intl` format method re-run every render (DOM-node + render argument).
- **Post-change:** cap/virtualize the list; precompute row view-models (format once on arrival); `shallowRef`/`markRaw` the read-only row arrays.
- **Correctness guard:** the tables render the same rows/values; a Vitest component test pins rendered output.

### T5.2 — Vite vendor chunk split + parallelize the independent-fetch waterfalls + the frontend minor batch [perf S7-P2, S7-P4, S7-P3, S7-P5..P13]
- Add `build.rollupOptions.output.manualChunks` vendor split + pin target (S7-P2, S7-P13); `Promise.all` the two waterfalls (S7-P4); move template `JSON.stringify` to `computed` (S7-P3); active-tab-only source stringify (S7-P5); `modulepreload` the landing chunk (S7-P10); remove the dead `@tanstack/vue-table` dep (S7-P11); `useIntervalFn` + `refreshing` flag for pollers (S7-P9); `defineModel` for dialogs (S7-P12); client-side list cache / keep-alive (S7-P7); admin stale-response guards (S7-P8).
- **Baseline/Post-change:** `vite build --report` chunk sizes (stable vendor hash) + request-timeline + render arguments; a Lighthouse pass if a browser is available.
- **Correctness guard:** Vitest unit tests green; app loads; data still populates.

---

## Workstream 6 — Grouped minor tail (Themes A–E; group by file, one task per area)

Schedule (not defer) the minors as grouped tasks — cheap fixes are cheap to do:
- **Merge CPU/alloc batch** [S1-P4 JCS (design: confirm hash isn't externally portable first), S1-P6 otherSources hoist, S1-P8 CVSS-vector guard, S1-P9 dup CWE sort, S1-P10 `slices.Sort`, S1-P11 `slices.Sorted(maps.Keys)`].
- **Feed adapter alloc batch** [S3-P7 re-marshal RawPayload via `json.RawMessage`, S3-P8 stream generic/CSAF, S3-P9 alias early-return, S3-P10 conditional `strings.Clone`, S3-P13 GHSA fixed-array marshal].
- **Search read-path batch** [S4-P2 sargable CVSS/EPSS + indexes, S4-P3 `pgx.Batch` detail fetch, S4-P4 pgx-native row collection, S4-P5 cap `/sources`, S4-P6 LATERAL watchlist count, S4-P7 list projection, S4-P8..P13].
- **Reports/AI batch** [S6-P5 digest scan reuse, S6-P7 per-channel payload, S6-P8/P9 Gemini init, S6-P10 `hex.EncodeToString`, S6-P11].
- **Infra per-request micro-allocs** [S10-P1 `/readyz` caching, S10-P4 query-guard (shared S8-P4/P5), S10-P5 lazy logger, S10-P6 status-label table, S10-P2 feeds N+1, S10-P3 RLSCheck batch; rate-limiter `RWMutex` S5-P8, S9-P6; replay-map eviction S5-P9].
- **Each grouped task:** baseline = alloc/round-trip argument for the group; correctness guard = existing package tests green + the specific behavior pinned; **don't** rewrite surrounding code — minimal change per item.

---

## Appendix: Findings identified but not fixed inline in this cycle (with named mechanism)

These are **scheduled** above but carry a design decision that needs Sam's call before implementation —
recorded here as the persistent record (none are severity/effort deferrals):

### EPSS batch-apply locking strategy  (finding S3-P1, task T1.4)
**Impact:** Critical   **Location:** `internal/feed/epss/adapter.go:250-287`
**Why flagged:** batching the apply changes the PLAN.md §5.3 advisory-lock + two-statement TOCTOU contract
shared with the merge pipeline. **Decision needed:** chunked-batch (keep per-CVE locks) vs staging-table
set-apply (new locking discipline). **Recommended:** chunked batches first (lower risk).

### `material_hash` JCS removal  (finding S1-P4, task W6 merge batch)
**Impact:** Major   **Location:** `internal/merge/hash.go:81-94`
**Why flagged:** dropping JCS changes every `material_hash` value (corpus re-hash + golden regen). **Decision
needed:** confirm `material_hash` is **not** an externally published/portable digest before removing JCS; if
it must stay portable, keep JCS (documented overhead) and instead canonical-emit directly.

### Realtime-eval decoupling depth  (finding S2-P5 / T1.5)
**Impact:** Major   **Location:** `internal/ingest/handler.go:192-210`
**Why flagged:** fully-async eval widens alert latency; per-page batching keeps it tight. **Recommended:**
per-page batching (default), not full async.

---
**Advisory:** after each workstream, run the slice's `*-bug-hunt-kickoff.md` over the diff. The
security-relevant suspected bugs (alert cap+cursor missed alerts; digest watchlist scoping; EPSS
partial-run; missing `http.TimeoutHandler`) should go through `bug-hunt-cycle` **independently** of this
perf plan — they are correctness, not performance.
