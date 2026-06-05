# S2 Alert evaluation engine — data-access & I/O lane

ABOUTME: Performance audit of the alert evaluation engine's data-access patterns (S2, FULL, HOT).
ABOUTME: Lane = data access & I/O. Covers realtime/batch/EPSS sweep query shapes, N+1, indexing, squirrel SQL sargability.

Scope read: `internal/alert/evaluator.go`, `internal/alert/cache.go`, `internal/alert/dsl/{compiler,field}.go`,
`internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go`, `internal/store/queries/alert_rules.sql`,
`internal/store/queries/alert_rule_channels.sql`, `migrations/000002` (cves DDL),
`migrations/000015` (alert_rules DDL), `migrations/000016` (alert_rule_runs / alert_events DDL),
`internal/ingest/handler.go` (realtime caller), `internal/notify/dispatcher.go` (fanout).

No runtime profiling available (no Docker). Confidence is `Strong-static` or `Heuristic` only — never `Measured`.

---

## Hot-path cost model (queries per evaluated CVE)

The realtime path is the dominant hot path: `internal/ingest/handler.go:202` calls
`EvaluateRealtime(ctx, patch.CVEID)` **once per CVE whose `material_hash` changed**, inside the
per-patch merge loop of every feed page. A single NVD/OSV ingest run mutates thousands of CVEs.

For one changed CVE, with `R` = number of globally-active non-EPSS-only rules and `M` = matches:

| Step | Where | Queries | Round-trips / tx |
|---|---|---|---|
| Load all active rules | `EvaluateRealtime` → `ListActiveRulesForEvaluation` | 1 (whole table, all orgs) | 1 bypass tx (2 stmts) |
| Candidate query, per rule | `evaluateRule` → `queryCandidates` (own `bypassTx`) | R | R bypass tx (≥2 stmts each) |
| Resolution read, per matching rule | `GetUnresolvedAlertEventCVEs` | ≤R | ≤R bypass tx |
| InsertAlertRuleRun + UpdateAlertRuleRun, per firing rule | `InsertAlertRuleRun` / `UpdateAlertRuleRun` | 2·(matching rules) | 2 bypass tx |
| InsertAlertEvent, per match | `InsertAlertEvent` | M | M bypass tx |
| Fanout per match: list channels + snapshot + per-channel upsert | `Dispatcher.Fanout` | M·(2 + C) | M·(…) |

So a single changed CVE costs **on the order of `1 + R + …` separate DB transactions**, and a feed
ingest of N changed CVEs costs **`N · (1 + R + …)`** transactions. The rule set and the candidate
query for a one-element candidate list are re-fetched/re-run from scratch for every CVE. This is the
core finding (CRITICAL #1 + #2 below).

---

## Findings

### [CRITICAL] Realtime path re-loads the entire active-rule set and re-runs one candidate query per rule for every single changed CVE — no batching across the ingest loop
**Location:** `internal/alert/evaluator.go:88-120` (`EvaluateRealtime`), called per-CVE at `internal/ingest/handler.go:202`; `internal/store/alert_rule.go:395-403` (`ListActiveRulesForEvaluation`); `internal/store/queries/alert_rules.sql:45-50`
**Problem:** The ingest merge loop invokes `EvaluateRealtime` once per CVE whose `material_hash`
changed. Each invocation calls `ListActiveRulesForEvaluation` — `SELECT * FROM alert_rules WHERE
status='active' AND is_epss_only=false AND deleted_at IS NULL ORDER BY id` across **all orgs** — then
iterates every rule and issues a *separate* candidate query (each in its own `bypassTx`) with the
single-element candidate list `[cveID]`. Nothing is amortized across the loop: for an ingest run that
changes N CVEs with R active rules, the engine performs **N full rule-table reads** and **N·R
candidate queries**, each as an independent transaction with a `SET LOCAL app.bypass_rls` round-trip.
The compiled-rule `RuleCache` (`cache.go`) avoids *recompiling*, but does nothing for the *rule-list
fetch* or the *per-rule SQL round-trips*. The natural shape is the inverse: load the active rule set
once per ingest batch (or cache it with version-keyed invalidation), accumulate the changed CVE IDs,
and run each rule's candidate query once over the whole `ANY($1)` batch — exactly what `queryCandidates`
already supports via `candidateIDs`.
**Impact:** Reachable on the single hottest path (every material change during every feed sync).
Per-occurrence: `1 + R` queries × N CVEs = **O(N·R) transactions/round-trips per ingest run** where
the achievable floor is **O(R) queries per batch**. With R in the tens–hundreds and N in the
thousands, this is the dominant data-access cost of the whole engine. Each query also re-pays a
`BeginTx` + `SET LOCAL` + `Commit` round-trip (3 extra round-trips per candidate query, see #3).
**Confidence:** Strong-static (call structure and SQL are explicit).
**Effort:** Cross-cutting — changes the realtime contract: `EvaluateRealtime(cveID)` → a batched
`EvaluateRealtime(cveIDs []string)` (or an evaluator-side accumulator), and the ingest loop must
collect changed IDs and flush per page/run instead of calling per CVE. Touches `internal/ingest`,
`internal/alert`, and the realtime-evaluator interface.
**Verification plan:** Count DB round-trips for an ingest of N changed CVEs against R rules before/after
(structural: assert one rule-list fetch + R candidate queries per batch, not per CVE). Correctness
guard: existing `TestEvaluateRealtime_*` (events fired once, dedup via ON CONFLICT, resolution
detection) must stay green; add a test that a 50-CVE batch with 5 rules issues 5 candidate queries,
not 250.

### [CRITICAL] alert_event / run / channel writes each open their own bypass transaction — N+1 transactions per match instead of one batched write
**Location:** `internal/store/alert_rule.go:248-331` (`InsertAlertRuleRun`, `UpdateAlertRuleRun`, `InsertAlertEvent`, `GetUnresolvedAlertEventCVEs`, `ResolveAlertEvent` — each wrapped in `withBypassTx`); `internal/store/store.go:48-67` (`withBypassTx` opens `BeginTx` + `SET LOCAL` + `Commit` every call); driven by `internal/alert/evaluator.go:398-464` (`evaluateRule`)
**Problem:** Every per-row write in `evaluateRule` is its own transaction. For a rule with M matches,
the evaluator issues: 1 `queryCandidates` tx + 1 `GetUnresolvedAlertEventCVEs` tx + M `InsertAlertEvent`
txns (each `BeginTx` → `SET LOCAL app.bypass_rls` → `INSERT … ON CONFLICT` → `Commit`) + up to M
`ResolveAlertEvent` txns + 2 run-row txns. `withBypassTx` (`store.go:48`) re-issues `SET LOCAL
app.bypass_rls='on'` on a fresh pooled connection for *every one* of these. The alert-event inserts
for a single rule against a candidate batch are independent rows that belong in **one** transaction
(or a single multi-row `INSERT … ON CONFLICT DO NOTHING RETURNING id`), and the run start/finish pair
is two writes that could be one tx. Instead each pays full transaction + RLS-setup overhead.
**Impact:** Reachable on every firing rule on realtime, batch, EPSS, and activation paths. Activation
amplifies it worst: a new rule's baseline scan walks the **whole corpus** in 1,000-row pages
(`evaluator.go:254-272`) and inserts one event per match each in its own transaction — for a broad
rule that is thousands of single-row transactions during one activation. Per-occurrence: `≈ 2M + 4`
transactions per (rule, batch) where the floor is `~2-3`. Each tx adds `BeginTx`+`SET LOCAL`+`Commit`
round-trips on top of the insert itself.
**Confidence:** Strong-static.
**Effort:** Contained — add a batched write path: a single `bypassTx` that runs the run-insert, a
multi-row `InsertAlertEvents`, the resolution updates, and the run-finish, returning the set of
newly-inserted event IDs (needed to gate fanout). `evaluator.go:432-461` and the `AlertRuleStore`
interface change; callers are all in `internal/alert`.
**Verification plan:** Assert transaction count per firing rule is constant (independent of M) after
the change; multi-row `INSERT … ON CONFLICT DO NOTHING RETURNING id` returns exactly the rows that
were inserted, preserving the "fan-out only if inserted" invariant (`alert_rule.go:281-303`).
Correctness guard: `TestEvaluateRealtime_FanoutNotCalledForDuplicateEvent` and the activation /
resolution tests must remain green.

### [MAJOR] Per-match fanout re-queries channels and re-fetches the CVE snapshot for every matched CVE — and per-channel UpsertDelivery is itself N+1
**Location:** `internal/notify/dispatcher.go:46-75` (`Fanout`), called per match at `internal/alert/evaluator.go:441`; `internal/store/alert_rule_channel.go:72-86` (`ListActiveChannelsForFanout`); `dispatcher.go:79-117` (`buildSnapshot` → `GetCVESnapshot`); per-channel loop at `dispatcher.go:62-72` (`UpsertDelivery`)
**Problem:** `Fanout` is invoked once per matched CVE inside `evaluateRule`'s match loop. For each
call it (a) re-runs `ListActiveChannelsForFanout` (a join `alert_rule_channels ⋈ notification_channels`)
for the *same rule* every time — the channel set is identical for all matches of one rule and should
be fetched once per rule, not once per CVE; (b) issues `GetCVESnapshot` per CVE (one extra query per
match); (c) loops channels issuing a separate `UpsertDelivery` per channel (C more queries). For a
rule with M matches and C bound channels, fanout alone is `M·(2 + C)` queries, of which the M channel
re-fetches are pure waste. The channel list could be loaded once when the rule fires and passed into
fanout.
**Impact:** Reachable whenever a rule matches ≥1 CVE on any delivery-enabled path. `M` channel-list
joins per rule are redundant; `M·C` upserts are inherent but could use a multi-row insert. Frequency
scales with match volume on the hot realtime path.
**Confidence:** Strong-static for the redundant channel re-fetch and per-CVE snapshot; Heuristic on
the `UpsertDelivery` batching win (debounce semantics may constrain it).
**Effort:** Contained — hoist `ListActiveChannelsForFanout` to once per firing rule (pass channels in,
or memoize per (ruleID) for the batch), and consider a batched delivery upsert. Touches
`internal/notify/dispatcher.go` and the evaluator's match loop.
**Verification plan:** Assert one channel-list query per firing rule (not per match). Correctness
guard: `TestFanout_*` (debounce append, multi-channel, suppressed/duplicate) must stay green.

### [MAJOR] Candidate query filters and projects on `lower(status)` / `lower(description_primary)` — non-sargable predicates and an unused over-fetched column
**Location:** `internal/alert/evaluator.go:470-518` (`queryCandidates`); mirrored in `internal/store/dsl_executor.go:140` and `internal/alert/dsl/compiler.go:117-138,277-340`
**Problem:** Every candidate query appends `lower(cves.status) NOT IN ('rejected','withdrawn')`
(`evaluator.go:474`) and selects `COALESCE(lower(cves.description_primary), '')` (`evaluator.go:483`).
(1) `lower(status)` wraps the column in a function with no matching expression index — the predicate
is non-sargable and is evaluated row-by-row as a filter. There is no index on `status` at all
(`migrations/000002`), so status filtering is post-fetch regardless; but the `lower()` wrapper also
prevents ever using one and forces a per-row `lower()` call. The status set is a small closed
vocabulary ("Analyzed","Rejected","Modified",…) — a plain `status NOT IN ('Rejected','Withdrawn')`
(or `status <> ALL`) over the canonical-cased values would be sargable and index-able. (2)
`lower(description_primary)` is computed in SQL for **every candidate row** even though the column is
only consumed by regex PostFilters (`cveSummary.Description`); when a rule has no regex PostFilter the
lowered description is fetched and discarded — over-fetch of a wide, frequently-TOASTed text column on
the hot path. The watchlist and `affected.*` EXISTS subqueries similarly wrap `lower(cap.ecosystem)`,
`lower(cap.package_name)`, `lower(wi.ecosystem)` (`compiler.go:124-138,287-339`) with no expression
indexes on `cve_affected_packages` (only plain `(ecosystem, package_name)` exists in
`migrations/000002:162`), so those joins seq-scan / can't seek.
**Impact:** The `lower(status)` filter and `lower(description_primary)` projection are on **every**
candidate query on **every** path (realtime, batch, EPSS, activation, DSL search). Per-row `lower()`
cost + heap detoast of description when unused. The non-sargable `lower(ecosystem/package_name)` in
watchlist/affected subqueries forces sequential scans of `cve_affected_packages` per outer CVE for
watchlist-scoped rules.
**Confidence:** Strong-static for non-sargability and the unused-description over-fetch; Heuristic on
detoast magnitude (depends on description length / TOAST threshold).
**Effort:** Contained — store/compare `status` in canonical case to drop `lower()` (or add an
expression index `lower(status)`); only project `description_primary` when the compiled rule has a
description/cve_id PostFilter; add expression indexes (or store normalized lowercase columns) on
`cve_affected_packages.lower(ecosystem)` / `lower(package_name)` if watchlist/affected rules are
common. The status normalization interacts with the merge pipeline (out-of-lane) — flag, don't change unilaterally.
**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` the candidate query before/after: confirm
`Rows Removed by Filter` on status drops to an index condition and `Buffers` for description detoast
disappears when no PostFilter. Correctness guard: candidate-cap and rejected/withdrawn-exclusion tests.

### [MAJOR] Batch / EPSS sweep buffers the entire changed-CVE window into one slice, then runs every rule over the full list — unbounded memory and a single giant `ANY($1)` per rule
**Location:** `internal/alert/evaluator.go:157-225` (`evaluateBatchPath`), specifically the page-accumulation loop at `:170-193` building `allCandidateIDs`, then `:201-217` running each rule over the whole slice
**Problem:** The batch and EPSS sweeps page through changed CVEs with correct keyset pagination
(`getCVEsModifiedSince` / `getCVEsEPSSUpdatedSince`, ordered `cve_id ASC`), but instead of evaluating
rules per page they **accumulate every candidate ID across all pages into one `allCandidateIDs`
slice** (comment at `:170-171` says this is to avoid duplicate run rows), then pass that entire slice
as `cves.cve_id = ANY($1)` to each rule's `queryCandidates`. After a large feed re-sync
(`date_modified_canonical` moves for tens of thousands of CVEs), `allCandidateIDs` holds the whole
window in memory and each rule's candidate query ships and matches against a massive array parameter.
The candidate query also still has `LIMIT candidateCap+1` (5001), so for any rule whose predicate is
broad the per-rule result silently goes `partial` once the changed window exceeds 5000 — the sweep
fails-closed on exactly the high-churn runs where it matters. The driver behind the per-page run-row
concern is real, but it can be solved by inserting the run row once and updating counters per page,
rather than materializing the whole window.
**Impact:** Reachable on every batch/EPSS sweep; cost scales with changed-window size W. Memory: O(W)
IDs held for the whole sweep. Query: each rule ships an O(W) array param and the planner must match a
huge `= ANY` against `cves`. Behavioral cliff at W>5000 (partial/fail-closed) is a correctness-shaped
performance trap (recorded below too).
**Confidence:** Strong-static for the buffering and the `ANY($1)` shape; Heuristic on the realistic
window size W.
**Effort:** Contained — evaluate rules per page (run-row started once per rule per sweep, counters
accumulated across pages), bounding memory and array size to `candidatePageSize` (1000) and removing
the global-window cap interaction. Localized to `evaluateBatchPath`.
**Verification plan:** Assert peak `allCandidateIDs` length is bounded by page size after refactor and
that one run row per rule per sweep is still produced. Correctness guard: cursor advances only after
all pages; existing batch/EPSS tests for cursor monotonicity and per-rule single-run-row.

### [MINOR] `ListActiveRulesForEvaluation` / `ListActiveRulesForEPSS` can't seek the partial index — leads with `org_id`, but the worker query has no `org_id` predicate
**Location:** `internal/store/queries/alert_rules.sql:45-57`; index `alert_rules_active_idx ON alert_rules (org_id) WHERE status IN ('active','activating') AND deleted_at IS NULL` (`migrations/000015:44-46`)
**Problem:** The cross-org worker queries filter `status='active' AND is_epss_only=false AND
deleted_at IS NULL` (and `has_epss_condition=true` for EPSS) with **no** `org_id` predicate. The only
supporting index, `alert_rules_active_idx`, leads with `org_id`. With no `org_id` in the WHERE the
planner can't seek; at best it does a full index scan of the partial index (still narrower than the
heap, but it cannot satisfy `is_epss_only=false` / `has_epss_condition=true` as index conditions, so
those are post-filters). On the realtime path this query runs once per changed CVE (see CRITICAL #1),
so even a cheap full scan is multiplied by N.
**Impact:** Small per-query cost but multiplied by the realtime frequency. Magnitude bounded by the
active-rule count (likely small), so MINOR on its own — its real cost is the N× multiplier from #1.
**Confidence:** Heuristic (no `EXPLAIN`; depends on row counts and planner choice).
**Effort:** Localized — a partial index on `(is_epss_only) WHERE status='active' AND deleted_at IS NULL`
(and an EPSS-condition partial index) would let the worker query seek; only worthwhile if #1's
per-CVE re-fetch is *not* eliminated. If #1 is fixed (load once per batch), this drops to negligible.
**Verification plan:** `EXPLAIN` the two worker queries; compare full-index-scan vs partial-seek.
Defer until #1 is decided — fixing #1 likely makes this moot.

### [MINOR] `GetCVEMaterialHash` is read twice per merged patch (pre- and post-merge) on the ingest hot path
**Location:** `internal/ingest/handler.go:167-210` (`GetCVEMaterialHash` at `:169` and `:194`)
**Problem:** To detect a material-hash change, the ingest loop reads the hash before merge and again
after, for **every** merged patch (not just changed ones) — two single-row `SELECT material_hash`
round-trips per patch on top of the merge itself. The merge pipeline recomputes and writes
`material_hash`; the post-merge value (and ideally a "changed" boolean) could be returned from the
merge call instead of a second point query. This is adjacent to S1 (merge) but the read pattern is
the trigger for S2 realtime evaluation.
**Impact:** 2 extra single-row queries per merged patch across all feeds. Bounded per-row cost but
runs at full ingest volume. Recorded as MINOR; the bigger ingest cost is #1.
**Confidence:** Strong-static (two explicit reads).
**Effort:** Contained — have the merge function return the pre/post hash (or a `changed` flag); cross
package boundary into `internal/merge`. Out of strict lane (merge), flagged for the S1 lane / coordinator.
**Verification plan:** Assert one fewer query per patch after threading the hash through the merge
return. Correctness guard: realtime evaluation still fires iff the hash actually changed.

---

## Notes / non-findings

- **Keyset pagination is correct.** `getCVEsModifiedSince` / `getCVEsEPSSUpdatedSince` /
  `getCVEsBatch` use `(date_modified_canonical > $1 AND cve_id > $2) ORDER BY cve_id ASC LIMIT $n` —
  no `OFFSET`. `cves_date_modified_canonical_idx (DESC)` and `cves_date_epss_updated_idx` exist
  (`migrations/000002:45-49`); the PK on `cve_id` serves the tiebreak. The sweep ordering is by
  `cve_id` while the index is on the date column, so the date predicate is a range filter and the sort
  is on the PK — acceptable, but note the date index is `DESC` while the cursor walks `cve_id ASC`;
  the planner will likely range-scan on date and sort, not index-order — fine for paged windows.
- **`alert_events` ON-CONFLICT lookup is indexed.** The table constraint
  `UNIQUE (org_id, rule_id, cve_id, material_hash)` (`migrations/000016:53`) auto-creates the btree the
  `ON CONFLICT DO NOTHING RETURNING id` upsert needs — no missing index there.
- **Resolution-detection read is indexed.** `alert_events_unresolved_idx (rule_id, org_id) WHERE
  last_match_state = true` (`migrations/000016:99-101`) exactly serves `GetUnresolvedAlertEventCVEs`.
- **RuleCache** correctly avoids recompilation (version-keyed); it is not a data-access problem, only
  that it doesn't help the rule-*list* fetch (#1).
- **DSL search path** (`ExecuteDSLQuery`, `dsl_executor.go`) shares the same `lower(status)` /
  watchlist non-sargability as #4 but is an API path, not the S2 hot worker path — same fix applies.

---

## Suspected Bugs (for follow-up)

- **Batch/EPSS sweep fail-closes on high-churn windows (`evaluator.go:201-217` + `queryCandidates`
  cap at `:491`).** When the accumulated changed-window exceeds `candidateCap` (5000), each rule's
  candidate query returns `partial=true` and the rule is recorded `partial` with **zero** matches for
  that sweep — and the cursor still advances (`:224`). A genuinely large modification window (large
  NVD re-sync) could cause rules to silently miss matches for that window with no retry. The cap was
  designed for regex candidate bounding, but here it also gates the batch sweep against the whole
  window. Performance-shaped (#6 mitigates by per-page evaluation), but the missed-match behavior is a
  correctness concern worth a closer look by the alert-correctness owner. Recording only, not chasing.
- **`afterID`-based keyset can skip CVEs when `date_modified_canonical` ties across a page boundary
  combined with `cve_id` ordering** — the WHERE uses `date_modified_canonical > $1 AND cve_id > $2`
  (AND, not a row-value `>`), so the second-and-later pages require BOTH date strictly greater AND
  cve_id strictly greater, which can drop rows with the same date but smaller cve_id than the page's
  last id. `dsl_executor.go` correctly uses row-value `(date, cve_id) < (?, ?)`, but
  `evaluator.go:603-609` uses separate `AND` predicates. Recording for the correctness owner.
