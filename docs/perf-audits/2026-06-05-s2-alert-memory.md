# S2 Alert evaluation engine — memory & allocation lane

ABOUTME: Performance audit of the alert evaluation engine focused on memory/allocation on the
ABOUTME: per-CVE realtime and per-candidate batch/EPSS evaluation hot paths.

Scope read: `internal/alert/evaluator.go`, `internal/alert/cache.go`,
`internal/alert/dsl/{compiler,postfilter,types,accessor,field}.go`,
`internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go`,
`internal/store/queries/alert_rules.sql`, `internal/ingest/handler.go` (call site).

Hot-path frame established from the actual call site: `internal/ingest/handler.go:202` calls
`EvaluateRealtime(ctx, patch.CVEID)` synchronously inside the per-patch merge loop, once per CVE
whose `material_hash` changed — up to ~10^6 times during a backfill. Inside `EvaluateRealtime`
(`evaluator.go:88`) the per-CVE cost is multiplied by the number of active non-EPSS-only rules
(`R`), because it loops every rule for the single CVE. So the allocation frame that matters is
**per (CVE × rule)** for realtime, and **per (rule × candidate-page)** for batch/EPSS.

---

### [CRITICAL] Full rule set re-loaded from Postgres on every realtime CVE (unmarshalled, re-scanned, discarded)

**Location:** `internal/alert/evaluator.go:90` (`ListActiveRulesForEvaluation`) → `internal/store/alert_rule.go:395` → `internal/store/queries/alert_rules.sql:45`; allocation amplified by `loadAndCompileRule` JSON unmarshal at `evaluator.go:527-528`.

**Problem:** `EvaluateRealtime` calls `e.rules.ListActiveRulesForEvaluation(ctx)` once **per CVE**. That method opens a bypass transaction (`SET LOCAL` round-trip + `BeginTx`/`Commit`), runs `SELECT * FROM alert_rules WHERE status='active' ...`, and materializes the entire active rule set into a fresh `[]generated.AlertRule` every single call. Each `AlertRule` row carries `Conditions json.RawMessage` and `WatchlistIds []uuid.UUID` — heap-allocated byte slices and UUID slices scanned per row, per CVE. During a 10^6-CVE backfill with `R` active rules, this allocates `~R` full rule structs (plus their `[]byte` condition blobs and watchlist slices) **10^6 times** and throws them all away. The `RuleCache` only memoizes the *compiled* AST keyed by `(ruleID, dslVersion)` — it does nothing to avoid re-fetching and re-scanning the raw rows, and `loadAndCompileRule` still JSON-unmarshals `rule.Conditions` into `[]dsl.Condition` on every cache *miss*, but the row fetch + scan happens unconditionally even on cache hits.

**Impact:** Reachability: direct backfill hot path (handler:202). Frequency: 10^6 × (1 query + 1 tx + R row-scans). Per-occurrence: one DB round-trip pair (BeginTx + `SET LOCAL` + SELECT + Commit) plus `R` × (struct + `[]byte` conditions + `[]uuid.UUID` watchlist) allocations, all immediately garbage. This is the single largest avoidable allocation source in the lane — the rule set changes on the order of minutes, not per-CVE.

**Confidence:** Strong-static — call structure and `withBypassTx` body (`store.go:48`) make the per-CVE fetch + per-row allocation certain.

**Effort:** Contained — introduce a rule-set snapshot cache in `RuleCache` (or a small loader) refreshed on a TTL / on rule-mutation eviction, returning the already-loaded `[]AlertRuleRow`. The realtime loop reads the snapshot instead of hitting the DB each CVE. Touches `cache.go`, `evaluator.go`, and the eviction call sites (rule create/update/delete handlers).

**Verification plan:** `go test -bench BenchmarkEvaluateRealtime -benchmem ./internal/alert/` with a seeded corpus and N active rules, asserting allocs/op and DB query count drop from O(per-CVE) to O(1) amortized. Complexity argument: rule fetch goes from 10^6 fetches to ~`(backfill_duration / TTL)` fetches. Correctness guard: existing `TestEvaluateRealtime_*` tests must still pass (matches, fanout, dedup); add a test that a rule update is observed by realtime eval within the snapshot TTL / after eviction.

---

### [MAJOR] Squirrel candidate query rebuilt and re-serialized to SQL for every (CVE × rule) and every (page × rule)

**Location:** `internal/alert/evaluator.go:470-495` (`queryCandidates`), called from `evaluateRule` at `:411`.

**Problem:** `queryCandidates` reconstructs the entire squirrel statement on every call: `sq.And{compiled.SQL, sq.Expr("lower(cves.status) NOT IN (...)")}`, optionally appends `sq.Expr("cves.cve_id = ANY(?)", pq.Array(candidateIDs))`, builds a `Select(...).From("cves")`, ranges `compiled.Joins` calling `.Join`, then `.Where(...).Limit(...).ToSql()`. `ToSql()` walks the whole Sqlizer tree, allocating a `strings.Builder`/`bytes.Buffer`, an `args []interface{}` slice, and intermediate strings — **every time**. The generated SQL string is *identical* across all 10^6 CVEs for a given rule (only the bound `cve_id` array parameter changes). For realtime that's `ToSql()` run `10^6 × R` times producing the same string; for batch/EPSS it's `R × pages`. The compiled rule already lives in `RuleCache` but the *serialized SQL + arg template* is recomputed from scratch each evaluation instead of being cached alongside the compiled AST.

**Impact:** Reachability: every evaluation path. Frequency: realtime `10^6 × R`; batch/EPSS `R × ⌈corpus/1000⌉`. Per-occurrence: full squirrel tree walk → one query string + `args` slice + `pq.Array` wrapper + several substring allocations. Constant-factor but multiplied by the highest frequency in the system.

**Confidence:** Strong-static — `ToSql()` allocates a builder and args slice by construction; the inputs are invariant per rule except the candidate-ID parameter.

**Effort:** Contained — at compile time, render the candidate-query SQL template once (status filter + joins + limit + a placeholder for `cve_id = ANY($n)`) and store the string on `CompiledRule`; at eval time only bind `pq.Array(candidateIDs)`. The `candidateIDs`-present vs `-absent` (dry-run / full-scan) variants are two fixed templates. Touches `dsl/compiler.go`, `dsl/types.go`, and `evaluator.go:queryCandidates`.

**Verification plan:** `-benchmem` on `queryCandidates` before/after, asserting allocs/op drops (no `ToSql` in the steady state). Correctness guard: golden-compare the cached template + bound args produce byte-identical SQL and args to the current `ToSql()` output for a representative rule set; existing evaluator integration tests pin behavior.

---

### [MAJOR] Batch/EPSS sweep materializes the entire candidate ID set in memory before evaluating any rule

**Location:** `internal/alert/evaluator.go:170-198` (`evaluateBatchPath`), `allCandidateIDs` accumulation.

**Problem:** The batch/EPSS loop pages candidate CVE IDs 1000 at a time but **appends every page into one `allCandidateIDs []string`** with no cap, then evaluates all rules against the whole slice. The stated reason (comment at `:170-171`) is to avoid duplicate `alert_rule_runs` rows per page — a correctness constraint, not a memory one. During a backfill or a wide cursor window this slice can hold the entire non-rejected corpus (~10^6 CVE-ID strings, each a separate heap allocation plus the backing array). Worse, that full slice is then passed to `queryCandidates` as `pq.Array(candidateIDs)` → `cve_id = ANY($1)` with up to 10^6 elements, which both balloons the arg encoding and is then `LIMIT candidateCap+1`-capped server-side anyway, so most of the materialized IDs cannot even contribute matches per query. Append into a nil slice also incurs repeated doubling/copy of the growing backing array (`memory` pack: missing preallocation).

**Impact:** Reachability: scheduled batch + EPSS sweeps (and any large cursor window). Frequency: per sweep. Per-occurrence: O(corpus) live `[]string` + backing-array regrowth, held for the entire rule loop (`R` iterations). Memory footprint scales with corpus size with no bound — the one place in the lane that reads a whole result set into memory where a bounded/streaming structure belongs.

**Confidence:** Strong-static — unbounded `append` across all pages is explicit in the loop.

**Effort:** Contained — restructure so the run-row bookkeeping (one run per rule per sweep) is decoupled from page iteration: either (a) insert the run row once per rule up front, then stream pages and accumulate per-rule match/candidate counts, or (b) chunk `allCandidateIDs` into `candidateCap`-sized windows. Pre-size the slice with `make([]string, 0, estimate)` if full materialization is retained short-term. Touches `evaluateBatchPath` and the run-accounting; ordering across pages is already irrelevant given `ON CONFLICT DO NOTHING`.

**Verification plan:** Heap-profile / `-benchmem` a synthetic 100k-candidate sweep asserting peak live `[]string` is bounded by page/window size, not corpus size. Correctness guard: existing batch/EPSS tests that assert exactly one `alert_rule_runs` row per rule per sweep, plus match counts, must remain green.

---

### [MINOR] `ApplyPostFilters` appends matches into an unpreallocated slice; per-rule allocation on every page

**Location:** `internal/alert/dsl/postfilter.go:12-23` (`ApplyPostFilters`), called at `evaluator.go:420` and `dsl_executor.go:206`.

**Problem:** `ApplyPostFilters` builds `var matched []T` and `append`s survivors with no preallocation. On the activation/dry-run/batch paths the input can be up to `candidateCap` (5,000) candidates; a low-selectivity regex (most rows pass) drives repeated slice doublings and a full copy of up to 5,000 `cveSummary`/wrapper values. The companion path in `dsl_executor.go:202-210` additionally allocates a `[]cvePostFilterTarget` wrapper slice and then a second `make([]generated.CVE, len(filtered))` copy-back — two full passes materializing the result twice per page.

**Impact:** Reachability: every rule with a regex postfilter on every page that survives the SQL prefilter. Frequency: per (rule × page). Per-occurrence: up to ~5,000-element slice growth + copy; the executor variant doubles it. Bounded by `candidateCap`, hence MINOR, but reached on the common "regex rule" path.

**Confidence:** Strong-static — nil-slice `append` and the double copy in the executor are visible.

**Effort:** Localized — `matched := make([]T, 0, len(candidates))` in `ApplyPostFilters`; in `dsl_executor.go`, filter in place (compute kept indices, `results = results[:n]`) rather than wrap-then-copy-back.

**Verification plan:** `-benchmem` on `ApplyPostFilters` with 5,000 candidates at 90% pass rate, asserting allocs/op drops to ~1. Correctness guard: `postfilter_test.go` AND/OR/negate cases must stay green; order-preservation asserted.

---

### [MINOR] Per-evaluation map allocations and single-element candidate slice in the realtime path

**Location:** `internal/alert/evaluator.go:94` (`candidateIDs := []string{cveID}`), `:433` (`matchedIDs := make(map[string]bool, len(matched))`), `:450` (`candidateSet`).

**Problem:** For realtime, every (CVE × rule) allocates a one-element `[]string{cveID}` slice (`:94` is per-CVE, reused across rules — acceptable), but `evaluateRule` allocates `matchedIDs` map (`:433`) and, when resolutions are checked, a `candidateSet` map (`:450`) on every call. For realtime, `len(matched)` and `len(candidateIDs)` are ≤1, so these maps carry the documented ~100-byte/entry map overhead to hold at most one key — a map where a direct comparison would do. Multiplied by `10^6 × R` evaluations these are pure waste, though each is small.

**Impact:** Reachability: realtime per (CVE × rule). Frequency: 10^6 × R. Per-occurrence: 1–2 tiny map allocations + the single-element candidate slice. Small per-op but high frequency; ranked MINOR because each allocation is bounded and tiny.

**Confidence:** Strong-static.

**Effort:** Localized — for the single-candidate realtime case, short-circuit resolution/matched bookkeeping (when `len(candidateIDs)==1` a slice scan or direct equality replaces the maps). Keep the map path for batch/activation where N is large.

**Verification plan:** `-benchmem` on `EvaluateRealtime` single-CVE single-rule, asserting map allocs eliminated for N=1. Correctness guard: resolution-detection tests (prev-matched CVE no longer matching) must stay green for both N=1 and N>1.

---

## Suspected Bugs (for follow-up)

- `internal/alert/evaluator.go:201-217` (`evaluateBatchPath` rule loop) and `:96-115` (`EvaluateRealtime`): the realtime `candidatesEval` returned from `evaluateRule` is `len(candidateIDs)` (`:414`, `:463`) — i.e. the *input* count, not the number actually scanned/evaluated post-SQL-filter. `alert_rule_runs.candidates_evaluated` therefore records input size, not evaluated size. Not a perf issue; flagging as a metrics-correctness discrepancy for follow-up. Not chased.
- `internal/alert/evaluator.go:416-418`: when `partial` (candidate cap exceeded) the function returns `len(candidateIDs)` as candidatesEval and `0` matches, but for the **batch** path `allCandidateIDs` may be far larger than `candidateCap`; the partial signal is per-rule-query but the reported candidate count is the whole batch. Cosmetic/metrics only. Not chased.
