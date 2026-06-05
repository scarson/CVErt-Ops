---
run_schema_version: 1
run_id: 2026-06-05-s2-alert
date: 2026-06-05T01:15:00Z
scope: "S2 — Alert evaluation engine (internal/alert/**, internal/alert/dsl/**, internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go)"
methodology:
  skill: performance-audit-cycle
  plugin_version: superpowers-plus@0.2.0 (vendored; version per source repo)
dispatch:
  model_requested: "opus (latest; Claude Code Agent tool)"
  reasoning_effort: "default (harness exposes no knob)"
  overridden_by_user: false
stack:
  - { ecosystem: go, framework: "Masterminds/squirrel", version: 1.5.4 }
  - { ecosystem: go, framework: stdlib+pgx, version: go1.26.2 / pgx5.9.2 }
currency_briefs:
  - { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); project on 1.26 — idiom findings Heuristic" }
lanes_run: [algorithmic, memory, data-access, concurrency, idiom-currency, cost-map]
lanes_skipped: { payload-startup: "no payload/startup surface (background evaluator)", dynamic: "no Docker/testcontainers + no corpus locally" }
finding_counts:
  by_impact: { critical: 2, major: 5, minor: 5 }
  by_lane: { algorithmic: 5, memory: 5, data-access: 6, concurrency: 5, idiom-currency: 1 }
  suspected_bugs: 4
regression:
  prev_run_id: null
  new: 12
  persisting: 0
  resolved: 0
---

# Performance Audit (consolidated + validated) — S2 Alert evaluation engine

**Scope:** internal/alert/**, internal/alert/dsl/**, store/{alert_rule,dsl_executor,alert_rule_channel}.go (+ alert SQL adjacent)
**Stack:** Go 1.26.2 · squirrel 1.5.4 (dynamic DSL→SQL) · pgx/v5 (simple protocol) · RE2 `regexp` (precompiled+cached)
**Lanes run:** 6 core (FULL). **Verification mode:** static-only. **Regression vs none:** 12 new.
Blind run; cross-validated against source. **Exceptional cross-lane agreement** — four independent lanes
converged on the same two criticals.

## Cross-cutting root cause: the realtime path is O(CVEs × Rules) where O(CVEs)+O(Rules) is achievable

`EvaluateRealtime(cveID)` (`internal/alert/evaluator.go:88`) is invoked **inline** from the serial ingest
merge loop (`internal/ingest/handler.go:202`) once per CVE whose `material_hash` changed (~10^6 during a
backfill). Each call (validated by reading the code): **(1)** re-fetches the **entire active rule set
across all orgs** (`ListActiveRulesForEvaluation`), then **(2)** loops every rule, and for each opens its
own bypass transaction + candidate SQL query to test predicates against the **single already-known CVE**.
So ingest throughput degrades **linearly with total tenant rule count**, not ingest volume, and the cost
is `CVEs × Rules × (rule-set fetch amortized + per-rule tx + query)`. The right shape is: cache/snapshot
the active rule set, and evaluate one CVE against all rules in a single pass (or batch CVEs per page as the
batch path already does). The `RuleCache` memoizes only the *compiled AST*, not the row fetch or the query.

## Critical Findings

### P1. Realtime evaluation re-loads the entire active rule set from Postgres on every changed CVE
**Lanes:** algorithmic, memory, data-access (critical), concurrency, cost-map (agreement ×5)  **Location:** `internal/alert/evaluator.go:90` → `internal/store/alert_rule.go:395` (`ListActiveRulesForEvaluation`, `alert_rules.sql:45`); driven per patch at `internal/ingest/handler.go:202`
**Fingerprint:** `data-access:alert/evaluator.go:EvaluateRealtime:rule-set-reload-per-cve`  **Status:** new
**Problem:** `EvaluateRealtime` calls `ListActiveRulesForEvaluation` at the top of every invocation, re-fetching and re-decoding all active rules (with `Conditions []byte` + `watchlist_ids`) once per changed CVE — ~10^6 throwaway full-rule-set fetches during a backfill. **Validated:** confirmed at `evaluator.go:90`; the cache only avoids `Compile`, not the list query/unmarshal.
**Impact:** reachability = every realtime eval (production ingest); frequency = per changed CVE × backfill volume; per-occurrence = one full-table-ish rule fetch + per-row decode. **Confidence:** Strong-static  **On cost map:** yes (High)
**Effort:** Contained — a TTL'd / change-invalidated active-rule snapshot (the cache already has an invalidation hook), or batch realtime eval per ingest page so the fetch amortizes across the page.
**Blast radius:** the snapshot must invalidate on rule create/update/activate so a new rule isn't missed; correctness-sensitive for a security product (a stale snapshot must not drop a just-activated rule).
**Verification plan:** query-count argument (rule fetches: per-CVE → per-page or per-TTL); correctness guard = test that activating a rule causes the next eval to see it within the invalidation window.

### P2. Realtime runs one candidate query in its own bypass transaction per (CVE × rule)
**Lanes:** algorithmic (critical), data-access (critical), concurrency (critical), cost-map (agreement ×4)  **Location:** `internal/alert/evaluator.go:96-115` → `evaluateRule` `:398` → `queryCandidates` `:470`; bypass tx `:409,:551`
**Fingerprint:** `data-access:alert/evaluator.go:evaluateRule:per-rule-query-per-cve`  **Status:** new
**Problem:** For one changed CVE the realtime loop opens R bypass transactions (`BeginTx` + `SET LOCAL app.bypass_rls`) and runs R candidate `SELECT`s (+ R resolution selects) to test predicates against a **single, already-fetched** row — `queryCandidates` already supports a batched `ANY($1)` list but realtime passes a size-1 array per rule. **Validated:** confirmed — `candidateIDs := []string{cveID}` then per-rule `evaluateRule`.
**Impact:** ~10^6 × R × (≥2 round-trips + tx setup). The dominant realtime DB cost. **Confidence:** Strong-static  **On cost map:** yes (High)
**Effort:** Contained — share one bypass tx per CVE; better, evaluate the CVE against all rules in one pass (in-process predicate eval on the already-known row, or one SQL pass over the rule set). **Blast radius:** preserve per-org isolation (rules carry `OrgID`); the bypass-tx scoping must stay correct.
**Verification plan:** round-trip argument (R tx+queries/CVE → 1); correctness guard = test that match results per rule are identical to the per-rule-query path for a multi-rule, multi-org fixture.

## Major Findings

### P3. The candidate SQL string is rebuilt and re-serialized (`squirrel.ToSql`) on every (CVE × rule)
**Lanes:** memory, algorithmic, idiom-currency  **Location:** `internal/alert/evaluator.go:470-495`
**Fingerprint:** `memory:alert/evaluator.go:queryCandidates:tosql-rebuild-per-call`  **Status:** new
**Problem:** `queryCandidates` runs the squirrel builder + `ToSql()` (string + args assembly) on every call, producing an **identical** SQL string ~10^6 × R times — only the bound `cve_id` `ANY(?)` argument varies. **Validated:** confirmed. The SQL text for a compiled rule is invariant; it could be cached on `CompiledRule`.
**Impact:** per-(CVE×rule) builder alloc + string assembly. **Confidence:** Strong-static  **Effort:** Contained — cache the rendered SQL on `CompiledRule`, vary only the bound array. (Statement *caching* is foreclosed by simple-protocol, but the *render* is the avoidable cost.)
**Verification plan:** alloc argument (one ToSql per rule vs per CVE×rule); guard = rendered SQL equality test.

### P4. Batch/EPSS sweep buffers the entire changed-window candidate set in memory, then binds it as one giant `ANY($1)` per rule
**Lanes:** memory, data-access, concurrency, cost-map  **Location:** `internal/alert/evaluator.go:172-198` (accumulate) → `:200-217` (per-rule scan)
**Fingerprint:** `memory:alert/evaluator.go:sweep:unbounded-candidate-buffer`  **Status:** new
**Problem:** The sweep appends all pages into one uncapped `allCandidateIDs []string` (up to the whole modified window) before evaluating any rule, then binds it as `ANY($1)` per rule — O(window) memory + a large array param, contradicting the project's streaming requirement. **Validated:** confirmed — the loop accumulates across pages (deliberately, to write one run row per rule per batch) then `evaluateRule(…, allCandidateIDs, …)` per rule.
**Impact:** peak memory = whole window; large bind param re-scanned per rule. Interacts with the 5000 `candidateCap` (see SB1). **Confidence:** Strong-static  **Effort:** Contained — evaluate per page (accumulate per-rule match counts across pages for the single run row) instead of buffering all IDs. **Blast radius:** preserve the one-run-row-per-rule-per-batch semantics while streaming.
**Verification plan:** peak-memory argument (window → one page); guard = match counts identical to the buffered path.

### P5. Realtime evaluation runs inline on the serial ingest loop, coupling ingest throughput to total rule count
**Lanes:** concurrency  **Location:** `internal/ingest/handler.go:192-210` → `internal/alert/evaluator.go:88-120`
**Fingerprint:** `concurrency:ingest/handler.go:realtime-eval-inline-blocking`  **Status:** new
**Problem:** Because realtime eval is called synchronously inside the per-patch merge loop, every changed CVE blocks the feed worker for `R × (tx + query)` before the next patch merges. Ingest latency scales with tenant rule count. **Validated:** confirmed (handler calls `eval.EvaluateRealtime` inline after merge).
**Impact:** ingest throughput degradation proportional to rule count. **Confidence:** Strong-static
**Effort:** Contained — **design decision:** decouple realtime eval from the merge loop (enqueue changed `cve_id`s for an async evaluator, or batch per page). Recommend **batch-per-page** (keeps the change signal precise; amortizes the rule fetch of P1) over fully async (which widens alert latency). Flagged for the operator; the safe default is per-page batching.
**Verification plan:** argument that ingest latency decouples from R; guard = realtime alerts still fire for every changed CVE (no dropped change signal).

### P6. The candidate query is non-sargable and over-fetches (`lower(status) NOT IN …`, unconditional `lower(description_primary)`, `lower()`-wrapped EXISTS subqueries)
**Lanes:** data-access  **Location:** `internal/alert/evaluator.go:470-518`; `internal/alert/dsl/compiler.go:117,266`
**Fingerprint:** `data-access:alert/evaluator.go:queryCandidates:nonsargable-status-filter`  **Status:** new
**Problem:** `lower(cves.status) NOT IN ('rejected','withdrawn')` applies `lower()` per row (no expression index); `lower(description_primary)` is projected for every row even when no regex PostFilter consumes it; watchlist/affected EXISTS subqueries wrap `lower(ecosystem/package_name)` with no matching expression indexes. **Validated:** confirmed at the cited lines; the status filter is shared with the search path (see cross-slice note).
**Impact:** per-row function eval + over-fetch on every candidate scan. **Confidence:** Strong-static  **Effort:** Contained — store/compare status in a normalized case (or add a `lower(status)` expression index / a `status` enum check), project `description_primary` only when a regex postfilter needs it, add expression indexes for the EXISTS predicates.
**Verification plan:** index-usage argument (status filter becomes index-eligible); guard = identical candidate sets.

### P7. Batch/EPSS sweep evaluates rules strictly serially though rules are independent
**Lanes:** concurrency  **Location:** `internal/alert/evaluator.go:200-217`
**Fingerprint:** `concurrency:alert/evaluator.go:sweep:serial-rule-loop`  **Status:** new
**Problem:** Rules produce independent, order-independent outputs over a shared read-only candidate set, but the sweep loops them serially. **Validated:** confirmed.
**Impact:** sweep wall-clock = Σ per-rule scan instead of max. **Confidence:** Strong-static  **Effort:** Contained — `errgroup.WithContext` + `SetLimit`. **Blast radius / guards:** the shared `totalMatches` accumulator must be synchronized; `SetLimit` must keep `concurrency × bypass-conns-per-rule` under the 25-conn pool; same-rule concurrent eval must not break resolution-detection atomicity (it won't across distinct rules). `alert_events` ON CONFLICT DO NOTHING makes the inserts idempotent.
**Verification plan:** argument (serial Σ → bounded-parallel max); guard = match totals identical with and without parallelism (race-free).

## Minor Findings

### P8. `ApplyPostFilters` appends matches into an unpreallocated slice; the executor then double-copies
**Lane:** memory  **Location:** `internal/alert/dsl/postfilter.go:12-23`, `internal/store/dsl_executor.go:202-210`  **Fingerprint:** `memory:alert/postfilter.go:unprealloc-append`  **Status:** new — nil-slice `append` over ≤5,000 candidates + a wrap-then-copy-back second materialization per page. Localized (prealloc to candidate count; avoid the copy-back).

### P9. Per-evaluation map allocations on the realtime single-candidate path
**Lane:** memory  **Location:** `internal/alert/evaluator.go:433,450`  **Fingerprint:** `memory:alert/evaluator.go:per-eval-map-alloc`  **Status:** new — `matchedIDs`/`candidateSet` maps allocated to hold ≤1 key per (CVE×rule), ~10^6×R times; degenerate to a direct comparison when the candidate set is size 1. Localized.

### P10. `dsl_executor` re-lowercases `DescriptionPrimary` per regex match, redundant with the SQL-side `lower()`
**Lane:** algorithmic  **Location:** `internal/store/dsl_executor.go:273` vs `evaluator.go:483`  **Fingerprint:** `algorithmic:alert/dsl_executor.go:redundant-lower`  **Status:** new — recompute-in-loop over the postfilter candidate set. Localized.

### P11. `containsStr` hand-rolled membership loop duplicates `slices.Contains`
**Lane:** idiom-currency  **Location:** `internal/alert/dsl/validator.go:224-231`  **Fingerprint:** `idiom-currency:alert/validator.go:containsStr`  **Status:** new — cold path (rule mutation), n≤12; pure currency swap (Go 1.21 `slices`), Heuristic, Localized.

### P12. Worker rule-list query cannot seek the `alert_rules_active_idx` (org_id-leading)
**Lane:** data-access  **Location:** `internal/store/queries/alert_rules.sql:45-57` vs `migrations/000015…:44`  **Fingerprint:** `data-access:alert_rules.sql:active-idx-misalign`  **Status:** new — the all-org active-rule scan can't use an `org_id`-leading index; mostly a multiplier on P1. Localized (a partial index `WHERE status='active'` ordered for the scan).

## Cross-slice references (owned elsewhere — for the roll-up)
- **Fan-out re-queries channels + re-fetches the CVE snapshot per matched CVE; per-channel `UpsertDelivery` is N+1** — `internal/notify/dispatcher.go:46-75`, invoked at `evaluator.go:441`. **Owner: S5** (notification delivery). The M channel-list joins are identical per rule (pure waste). Recorded here because S2 invokes it; audited under S5.
- **Redundant 2× `GetCVEMaterialHash` per patch** — `internal/ingest/handler.go:169,194`. **Owner: S3 P4.** S2's data-access lane independently re-flagged it.
- **Non-sargable `lower(status) NOT IN …` status filter** also appears on the **S4** search/read path (same `cves` predicate) — note for S4 cross-check.

## Execution Cost Map (architectural awareness)
> Full map in `2026-06-05-s2-alert-cost-map.md`. Realtime cost = CVE × global-rule-count × (several txns
each); the two structural multipliers are re-listing all rules per CVE (P1) and one tx+query per rule
against a size-1 candidate set (P2). Batch/EPSS already amortize (one query per rule over the window,
regex compiled once, cap-bounded postfilter). Remaining concentration is **DB round-trips + transaction
setup, not Go CPU**. The regex postfilter is correctly bounded (≤5,000, precompiled) — **not** a finding.

## Measurability
Observable in prod only with per-eval rule-count + round-trip counters and realtime-eval duration vs
ingest-loop time. Recommend instrumenting before P1/P2 so the win is measured.

## Suspected Bugs (for follow-up — NOT addressed here)
> Two are **security-relevant (missed alerts)** and warrant a bug-hunt. Kickoff:
> `docs/perf-audits/2026-06-05-s2-alert-bug-hunt-kickoff.md`.

### SB1. Batch/EPSS sweep can silently skip matches when the window exceeds the 5,000 candidate cap, yet advances the cursor (MISSED ALERTS)
**Location:** `internal/alert/evaluator.go:172-225` (accumulate-then-`evaluateRule` with `candidateCap`) → `writeCursor`
**What looks wrong:** when `allCandidateIDs`/matches exceed the cap, `evaluateRule` returns `partial=true` (fail-closed), but the sweep still `writeCursor`s past the whole window — so candidates beyond the cap are never evaluated and never revisited. **Validated as plausible by reading the code** (cursor is written after the rule loop regardless of `partial`). High stakes for a security product. Record + verify; do not fix in this audit.

### SB2. (LIKELY FALSE POSITIVE — verify) keyset predicate uses separate `date > $1 AND cve_id > $2`
**Location:** `internal/alert/evaluator.go:595-615` (`getCVEsModifiedSince`)
**What a lane flagged:** separate predicates vs a row-value `(date,cve_id)` keyset could skip same-date rows. **Cross-validation correction:** this query `ORDER BY cve_id ASC` with a **fixed** `date_modified_canonical > since` floor — it pages by `cve_id` alone within the window, which is complete (date is a filter, not a sort key). I assess this as **likely not a bug**; recorded so the hunter confirms rather than trusting the lane.

### SB3. `candidates_evaluated` metric records input slice length, not rows actually evaluated
**Location:** `internal/alert/evaluator.go:414,463` — metrics correctness, not perf/correctness of alerts.

### SB4. Parallelizing the sweep (P7) naively races the shared `totalMatches` accumulator
**Location:** `evaluator.go:200-217` — a *guard* for the P7 fix, not a current bug.

---
**Disposition:** all 12 findings default to **FIX**. P5 (decouple realtime from ingest) carries a **design
decision** (per-page batching recommended) recorded inline; P1/P7 carry correctness guards (cache
invalidation; race/pool limits). No severity/effort deferral. SB1 (missed alerts) handed to bug-hunt.
