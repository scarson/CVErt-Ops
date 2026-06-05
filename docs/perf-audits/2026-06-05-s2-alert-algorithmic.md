# S2 Alert evaluation engine — `algorithmic` lane

ABOUTME: Performance audit of the alert evaluation engine focused on algorithmic complexity & data structures.
ABOUTME: Covers internal/alert/** (evaluator + DSL compiler/postfilter/validator) and internal/store alert_rule + dsl_executor.

Scope read: `internal/alert/evaluator.go`, `internal/alert/cache.go`,
`internal/alert/dsl/{compiler,postfilter,validator,accessor,field,types,parser}.go`,
`internal/store/alert_rule.go`, `internal/store/dsl_executor.go`,
`internal/store/queries/alert_rules.sql`, and the realtime call site
`internal/ingest/handler.go:163-211`.

Hot-path model (confirmed):
- **Realtime** (`EvaluateRealtime`, `evaluator.go:88`) is called inline from the ingest merge loop
  (`internal/ingest/handler.go:202`), **once per patch whose `material_hash` changed**. During a
  backfill that is ~10^6 invocations, serialized inside the feed worker.
- Per invocation, the realtime path does: 1× `ListActiveRulesForEvaluation` (loads ALL active
  non-EPSS rules across ALL orgs), then loops every rule and runs a per-rule candidate SQL query
  scoped to the single changed CVE.
- So realtime cost ≈ **(CVEs changed) × (1 + R) DB round-trips × per-rule constant work**, where
  `R` = global active non-EPSS rule count.

The findings below are ranked by aggregate cost on that model.

---

### [CRITICAL] Realtime path re-loads the entire global rule set from the DB on every changed CVE
**Location:** `internal/alert/evaluator.go:90` (`EvaluateRealtime` → `e.rules.ListActiveRulesForEvaluation`); query at `internal/store/queries/alert_rules.sql:45-50`; called per patch at `internal/ingest/handler.go:202`.
**Problem:** `EvaluateRealtime` opens with `ListActiveRulesForEvaluation(ctx)`, which issues `SELECT * FROM alert_rules WHERE status='active' AND is_epss_only=false AND deleted_at IS NULL ORDER BY id` — the complete active-rule set for **all orgs** — and is executed **once per changed CVE**. The rule set changes on the order of a rule-edit (rare), but it is re-fetched, re-scanned, and re-materialized 10^6 times during a backfill. Each call also drives `loadAndCompileRule` per rule; the compiled output is cached (`cache.go`) but the `[]AlertRuleRow` slice itself (with `conditions` JSONB, `watchlist_ids` arrays) is freshly fetched and allocated every time.
**Impact:** Reachable on the single hottest path. Per changed CVE: 1 full-table-ish scan of `alert_rules` + a row decode of every active rule (each row carries a JSONB `conditions` blob + a UUID array). Aggregate ≈ **10^6 × (rule-list query + R row decodes)**. With even 200 active rules this is 2×10^8 row decodes and 10^6 redundant SQL round-trips that return identical data between rule edits. The work is O(CVEs × R) where it should be O(CVEs) plus O(R) reload-on-change.
**Confidence:** Strong-static — call structure is unconditional; `handler.go:202` calls it per patch; no caching of the rule list exists (`RuleCache` caches only *compiled* rules keyed by `(rule_id, dsl_version)`, not the list/snapshot of which rules are active).
**Effort:** Contained — add a rule-set snapshot cache (the existing `RuleCache` is the natural home, or a sibling `activeRuleSnapshot` with a version/generation counter bumped on rule create/update/delete/status-change). The evaluator already has the eviction hooks pattern (`RuleCache.Evict`). Realtime then reads the cached snapshot instead of querying. Touches `evaluator.go` + the rule mutation handlers that must invalidate.
**Verification plan:** Complexity argument — current realtime is O(CVEs × (rule-list-query + R)); a snapshot-cached rule set makes the list O(1) amortized (rebuild only on rule mutation), reducing per-CVE DB round-trips from `1 + R` to `R` (and see next finding for collapsing the `R`). Correctness guard: `TestEvaluateRealtime_*` (fanout, dedupe, resolution) must stay green; add a test that a rule created/updated mid-stream is picked up (snapshot invalidation) so the cache doesn't serve a stale rule set.

---

### [CRITICAL] Realtime evaluates each rule with its own SQL query against the single changed CVE — O(R) round-trips per CVE instead of one
**Location:** `internal/alert/evaluator.go:96-115` (per-rule loop) → `evaluateRule` (`:398`) → `queryCandidates` (`:470-518`); per-rule `bypassTx` at `:409`/`:551`.
**Problem:** For one changed CVE, the realtime loop iterates every active rule and, per rule, opens a **new bypass transaction** (`bypassTx`: `BEGIN` + `SET LOCAL app.bypass_rls` + query + `COMMIT`) and runs a `SELECT cves.cve_id, material_hash, lower(description_primary) FROM cves [joins] WHERE <rule predicate> AND status NOT IN(...) AND cve_id = ANY(ARRAY['the-one-cve']) LIMIT 5001`. So a single CVE is re-fetched from `cves` (and re-joined to `cve_search_index` / `watchlist_items` / `cve_affected_packages`) once **per rule**. That is `R` transactions + `R` queries + `R` row-decodes of the *same* CVE row, where the rule predicate is just a boolean test on one already-known row. Resolution detection (`GetUnresolvedAlertEventCVEs`, `:426`) adds another per-rule query, and each match adds an `InsertAlertEvent` in its own bypass tx (`:436`).
**Impact:** Reachable on the hottest path; multiplies the previous finding. Per changed CVE the DB does `R` BEGIN/COMMIT pairs + `R` candidate SELECTs (each potentially with a watchlist `EXISTS` subquery against `cve_affected_packages`/`cve_affected_cpes`, or an FTS join) + up to `R` resolution SELECTs — all to test predicates against a single row. Aggregate ≈ **10^6 × R × (≥2 SQL round-trips + tx overhead)**. The per-occurrence cost is dominated by transaction + round-trip overhead, not query selectivity, so it does not amortize. This is the single largest cost driver in the realtime path.
**Impact note (design):** The clean algorithmic fix is to fetch the one changed CVE's evaluable fields **once** and evaluate all rule predicates in-process (the predicates are simple comparisons / set membership / regex already modeled by the DSL), OR to push all rules into one SQL pass. The current shape pushes each predicate to SQL independently, which is the wrong granularity for an N=1 candidate set.
**Confidence:** Strong-static — `queryCandidates` is called once per rule (`evaluator.go:103` inside `for i := range rules`), each wrapped in its own `bypassTx`; `candidateIDs` is always the single-element `[]string{cveID}` for realtime (`:94`).
**Effort:** Cross-cutting — collapsing R queries into one requires either (a) an in-process evaluator that loads the CVE's fields once and runs compiled predicates in Go (a new evaluation mode parallel to the SQL-push path), or (b) a single SQL pass that tests all rules at once (e.g., `LATERAL`/`CASE` per rule), plus reusing one bypass tx for the whole CVE instead of one-per-rule. Reusing a single bypass tx per CVE (cheap win) is Contained; the full in-process predicate evaluation is Cross-cutting.
**Verification plan:** Complexity argument — realtime per CVE goes from `R` transactions + `≥R` candidate queries to **1 transaction + 1 CVE fetch + R in-process predicate evals** (or 1 batched SQL pass). For N=1 candidates the regex/comparison work in Go is trivially bounded. Correctness guard: the full `evaluator_test.go` realtime suite (match, no-match, dedupe via `ON CONFLICT`, resolution detection, EPSS-only exclusion) must stay green; add a benchmark asserting per-CVE DB round-trips are constant in `R` after the change. **Do not** change resolution semantics (`alert_events` UNIQUE + `ON CONFLICT DO NOTHING RETURNING id` fan-out-only-on-insert must be preserved).

---

### [MINOR] `bypassTx` is opened per rule rather than once per CVE in the realtime loop
**Location:** `internal/alert/evaluator.go:96-115` (loop) and `:409` (`evaluateRule` opens `bypassTx` internally); helper at `:551-575`.
**Problem:** Even before collapsing the per-rule queries (previous finding), the realtime loop opens a separate transaction for every rule's candidate query: `BEGIN`, `SET LOCAL app.bypass_rls = 'on'`, query, `COMMIT`. The `SET LOCAL` + BEGIN/COMMIT is fixed overhead repeated `R` times per CVE for what is read-only work that could share one read-only transaction. (Resolution and insert paths use their own `withBypassTx` in the store layer, compounding the transaction count.)
**Impact:** Reachable per changed CVE; `R` extra BEGIN/COMMIT + `SET LOCAL` statements per CVE, ≈ 3×R extra round-trips/statements per CVE on top of the queries themselves. Aggregate ≈ 10^6 × R × (tx-setup overhead). Subsumed by the previous finding if that is fixed; listed separately because hoisting the transaction is a small, independent, low-risk win that helps even without the larger refactor.
**Confidence:** Strong-static — `evaluateRule` calls `e.bypassTx(...)` once per invocation, and it is invoked once per rule.
**Effort:** Contained — pass a shared `*sql.Tx` (read-only bypass) into `evaluateRule` for the realtime/batch loop so the candidate queries reuse one transaction; the inserts/resolutions still need write transactions (or fold them in). Touches `evaluateRule`'s signature and its callers.
**Verification plan:** Count BEGIN statements per CVE before/after (should drop from `R` to 1 for the candidate-query phase). Correctness guard: realtime + batch tests stay green; ensure `SET LOCAL app.bypass_rls` is still set on the shared tx.

---

### [MINOR] Resolution detection allocates a per-CVE candidate-set map even when there are no previously-matched events
**Location:** `internal/alert/evaluator.go:449-461` (and the `matchedIDs` map at `:433`).
**Problem:** In `evaluateRule`, after computing matches it builds `candidateSet := make(map[string]bool, len(candidateIDs))` and populates it from `candidateIDs`, then iterates `prevMatched`. For the realtime path `candidateIDs` is a single element, so the map is built to hold 1 key — a map allocation (~bucket + hmap header) to answer a single membership test that a direct `prevID == cveID` comparison would answer. The `matchedIDs` map (`:433`) is similarly allocated even when `matched` is empty (common — most CVEs match no rule). This runs inside the per-rule loop, i.e. up to `R` times per CVE.
**Impact:** Reachable per (CVE × rule). Two small map allocations per rule-eval where N (candidates) is 1 in realtime; aggregate ≈ 10^6 × R × 2 map allocs, most servicing a 0- or 1-element set. Pure-Go allocation/GC pressure, no query cost. Smaller than the query findings but on the same multiplied path.
**Impact note:** For realtime (single candidate) the whole resolution block degenerates to: "if this one CVE was previously matched and no longer matches, resolve it" — a direct comparison, no maps. The map-based structure is correct for the batch path (many candidates) but is the wrong container for N=1.
**Confidence:** Strong-static — allocation sites are unconditional within the function; `matchedIDs` is allocated before the match loop, `candidateSet` whenever `prevMatched` is non-empty.
**Effort:** Localized — guard the `matchedIDs` allocation on `len(matched) > 0`, and special-case the N=1 candidate path (or build `candidateSet` lazily / skip the map when `len(candidateIDs)==1`). One function.
**Verification plan:** `-benchmem` on a single-CVE single-rule `evaluateRule` asserting the map allocs drop to zero when there are no matches and no prev-matched events. Correctness guard: resolution tests (prev-matched CVE no longer matching for both N=1 and N>1) stay green.

---

### [MINOR] `pq.Array(candidateIDs)` rebuilt and `combined sq.And` reassembled on every `queryCandidates` call
**Location:** `internal/alert/evaluator.go:471-491` (`queryCandidates`).
**Problem:** Each call rebuilds the squirrel statement: a fresh `sq.And{compiled.SQL, sq.Expr("lower(cves.status) NOT IN (...)")}`, appends the `cve_id = ANY(?)` expr, re-applies joins, and re-renders to SQL via `ToSql()`. The static parts (`status NOT IN`, the join list, the compiled predicate) are identical across every call for a given rule; only the candidate-ID array varies. squirrel's `ToSql` walks the expression tree and allocates the query string + args slice every time. On the realtime path this re-renders `R` queries per CVE × 10^6 CVEs.
**Impact:** Reachable per (CVE × rule). Per call: squirrel tree walk + string build + `pq.Array` wrap + args slice alloc. Aggregate ≈ 10^6 × R query-string renders. Constant-factor allocation cost; meaningful only because of the 10^6×R multiplier. Largely subsumed if the per-rule-query design (CRITICAL #2) is replaced, but worth noting as the cost of the current shape.
**Confidence:** Heuristic — squirrel re-renders on each `ToSql`; the exact allocation count depends on squirrel internals, but the rebuild-per-call structure is certain from the code.
**Effort:** Localized→Contained — if the per-rule-query design is kept, the rendered SQL string for a rule is invariant except for the bound `ANY(?)` parameter, so the query text could be rendered once at compile time and cached on `CompiledRule` (only the args vary). Folds naturally into the `CompiledRule` cache.
**Verification plan:** `-benchmem` comparing repeated `queryCandidates` calls for one compiled rule; assert the SQL-string render allocations are hoisted out of the per-call path. Correctness guard: golden SQL string for a representative rule unchanged.

---

### Notes considered and dismissed (not findings)

- **Regex compiled per-evaluation?** No — regex patterns are compiled once in `dsl.Compile` (`compiler.go:43`) into `PostFilter.Pattern *regexp.Regexp`, and the `CompiledRule` is cached by `RuleCache` keyed on `(rule_id, dsl_version)` (`cache.go`). `ApplyPostFilters`/`matchesPostFilters` (`postfilter.go`) reuse the compiled `*regexp.Regexp` and do not recompile. This is the correct pattern; no finding.
- **Postfilter over the 5000-candidate cap** (the lane's flagged suspicion): `ApplyPostFilters` is O(candidates × filters) with a `MatchString` per (candidate × filter). The candidate set is hard-capped at `candidateCap = 5000` (fail-closed `partial` above that, `evaluator.go:514`, `queryCandidates` `LIMIT 5001`), and filters per rule are small. So the postfilter is provably bounded (≤5000 × small) and runs only after SQL pre-selection — **not** an accidental quadratic. The cap is the correct guard. No finding. (For realtime N=1 it is trivial.)
- **`RuleCache.Evict` is O(n) over all cached rules** (`cache.go:46-53`) — it scans the whole map to delete a rule's versions. This runs only on rule update/delete (cold, admin-frequency), with `n` = number of cached compiled rules. Provably bounded small-n on a cold path; not a finding per calibration (theoretical big-O on bounded small n).
- **Validator/parser** (`validator.go`, `parser.go`) run only at rule create/update (cold path). `containsStr` linear scans over tiny op/enum slices are bounded-small. Not findings.
- **Batch/EPSS paths** (`evaluateBatchPath`, `:157`) collect all candidate IDs across pages into one `allCandidateIDs` slice, then run each rule once against the whole set via `ANY(?)` — this is the *correct* batching shape (one query per rule for the whole window, not per CVE). The growth of `allCandidateIDs` via `append` without preallocation is a memory-lane concern, not algorithmic. The batch path does not exhibit the per-CVE × per-rule quadratic that realtime does.

---

## Suspected Bugs (for follow-up)

- `internal/alert/evaluator.go:414,463` — `evaluateRule` returns `len(candidateIDs)` (the *input* count) as `candidatesEvaluated`, not the number actually fetched/evaluated post-SQL-filter. So `alert_rule_runs.candidates_evaluated` records the input candidate-set size rather than rows evaluated. Metrics/observability discrepancy, not a perf issue. (Also noted by the memory lane.) Not chased.
