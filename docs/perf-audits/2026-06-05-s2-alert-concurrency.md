# S2 Alert Evaluation — Concurrency & Parallelization Audit

ABOUTME: Performance audit of the alert evaluation engine for the concurrency lane (both exploit and defend directions).
ABOUTME: Covers realtime/batch/EPSS/activation paths, the rule cache, regex postfilter, and channel fan-out.

**Lane:** concurrency · **Date:** 2026-06-05 · **Scope:** `internal/alert/**`, `internal/alert/dsl/**`,
`internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go`, plus the realtime call site in
`internal/ingest/handler.go`. No runtime profiling available — all findings `Strong-static` or `Heuristic`.

The engine is correct and conservative: `alert_events` insert is idempotent (`ON CONFLICT DO NOTHING
RETURNING id`, `alert_rule.go:281-303`), fan-out fires only when a row was actually inserted
(`evaluator.go:440`), and the rule cache is `sync.RWMutex`-guarded (`cache.go`). That correctness floor
is exactly what makes several of the serial loops safe to parallelize — and it also bounds the blast radius
of the one real DEFEND finding. Findings below are ordered by aggregate impact.

---

### [CRITICAL] Realtime eval blocks the serial ingest merge loop — N rules × full SQL round-trip per changed CVE, inline

**Location:** `internal/ingest/handler.go:192-210` (call site) → `internal/alert/evaluator.go:88-120` (`EvaluateRealtime`)
**Problem:** The merge loop calls `eval.EvaluateRealtime(ctx, patch.CVEID)` synchronously, inside the
per-patch `for _, patch := range result.Patches` loop, every time a CVE's `material_hash` changes. Ingest
cannot fetch/merge the next patch until realtime evaluation of the current one finishes. `EvaluateRealtime`
itself is fully serial: it calls `ListActiveRulesForEvaluation` (one query loading **every active rule across
all orgs**, `evaluator.go:90`), then loops those rules (`:96-115`) and, for each, runs `evaluateRule` →
`bypassTx` → `queryCandidates` — a separate transaction + `SELECT ... cve_id = ANY($candidateIDs)` SQL
round-trip against `cves` with the rule's joins. So per changed CVE the ingest thread blocks on
`R` sequential DB round-trips (R = global active-rule count), plus `InsertAlertRuleRun`/`UpdateAlertRuleRun`
(two more bypass transactions) for every matching/erroring rule. The merge loop is described as serial
"today" — this makes realtime alerting the dominant per-CVE cost on the ingest hot path, and it scales with
*total tenant rule count*, not with the tenant that owns the CVE (the CVE corpus is global).
**Impact:** Reachability: every feed ingest page, every changed CVE. Frequency: up to ~10^6 CVEs on a
backfill, thousands/day steady-state, × R active rules. Per-occurrence: R serial DB round-trips on the
critical path before ingest can advance. As R grows (more tenants, more rules) ingest throughput degrades
linearly with no relation to ingest volume. This is the single highest-aggregate-cost item in the lane.
**Confidence:** Strong-static (call site is inline in the loop; `EvaluateRealtime` body is a serial rule loop with per-rule tx).
**Effort:** Contained (one module + the ingest call site). Two independent levers:
  1. **Decouple from the merge loop (DEFEND).** Don't run realtime eval inline. Collect changed CVE IDs
     during the merge loop and either (a) enqueue a realtime-eval job per changed CVE (the activation path
     already uses `job_queue`; reuse it), or (b) drain a buffered channel into a small bounded worker pool
     after each page commits. Ingest throughput then decouples from R entirely. This is the structural fix.
  2. **Parallelize the rule loop within one CVE (EXPLOIT).** Rules are independent: each writes its own
     `alert_events` rows (unique on `(org_id, rule_id, cve_id, material_hash)`, idempotent insert), its own
     `alert_rule_runs` row, and `totalMatches` is a sum (order-independent). Fan out `evaluateRule` across
     rules with `errgroup.Group` + `g.SetLimit(n)` where n is sized against the pool (see DEFEND finding on
     pool exhaustion). Guard: each goroutine must accumulate its `matchCount` into a local and sum under the
     errgroup join (or use atomics) — do not write `totalMatches` from multiple goroutines unsynchronized.
**Verification plan:** Argue R-round-trips-per-CVE from the loop structure (no measurement available).
Bench `EvaluateRealtime` with R=1 vs R=50 active rules against a single CVE to show linear wall-clock growth,
then the same after parallelization/decoupling. Correctness guard: the realtime fan-out tests
(`TestEvaluateRealtime_FanoutCalledForNewEvent`, `_FanoutNotCalledForDuplicateEvent`,
`_FanoutErrorContinuesProcessing`, evaluator_test.go) and the ingest hash-change tests
(`handler_test.go:670-766`, asserting eval called exactly once per changed hash, zero on unchanged) must
stay green — they pin that decoupling does not change *which* CVEs get evaluated or double-fire.

---

### [MAJOR] Batch/EPSS sweep evaluates every rule against every candidate strictly serially — embarrassingly parallel work left on the table

**Location:** `internal/alert/evaluator.go:200-217` (`evaluateBatchPath` rule loop), `:124-142` (callers)
**Problem:** After collecting `allCandidateIDs` for the window, the sweep loops rules serially
(`for i := range rules`), and inside each iteration `evaluateRule` runs one `bypassTx`/`queryCandidates`
SQL round-trip against the (potentially large) candidate set, then `ApplyPostFilters`, then per-match
`InsertAlertEvent` + optional `Fanout`, then resolution detection. None of this overlaps: rule *k+1* waits
for rule *k*'s SQL, regex, and inserts to finish. This is the textbook "independent sub-tasks executed
serially that could be fanned out" pattern from the Go pack. The candidate set is shared and read-only;
rule outputs are independent (distinct `rule_id` in every `alert_events` / `alert_rule_runs` row); the loop
only accumulates `totalMatches` as an order-independent sum. The batch/EPSS jobs are background, so latency
is less critical than the realtime path — but a daily EPSS sweep or a backfill batch over a large window
× many rules is a long serial job that idles the pool waiting on one rule at a time.
**Impact:** Reachability: every batch tick and every EPSS daily sweep. Frequency: periodic, but each run is
O(rules × candidate-set-SQL). Per-occurrence: R sequential SQL+regex+insert passes that could overlap up to
the pool/limit. Lower reachability-frequency than realtime, hence MAJOR not CRITICAL.
**Confidence:** Strong-static (serial `for` over rules, per-rule tx and inserts).
**Effort:** Contained. Wrap the rule loop in `errgroup.WithContext` + `g.SetLimit(n)`; n bounded by pool
size (DB_MAX_CONNS=25, `config.go:20`) minus headroom for ingest/API. Each rule already opens its own
transaction, so concurrency is just removing the false serialization. Guard: accumulate `totalMatches` per
goroutine and sum at join (or `atomic.AddInt64`); keep `InsertAlertRuleRun`/`UpdateAlertRuleRun` inside the
per-rule goroutine so run rows stay 1:1 with rules.
**Verification plan:** Complexity argument: serial = Σ(rule_k cost); parallel = max over windows of n.
Bench `EvaluateBatch` with a seeded corpus (`SeedCorpus`) and R≈20 rules, serial vs limited-errgroup.
Correctness guard: the batch/EPSS evaluator tests (one `alert_rule_runs` row per rule per batch — the
comment at `:170-172` is the invariant) plus resolution-detection tests must stay green; assert run-row
count == rule count after a parallel sweep.

---

### [MAJOR] `ListActiveRulesForEvaluation` re-queried on every realtime invocation — no shared cached rule set across the ingest loop

**Location:** `internal/alert/evaluator.go:90` inside `EvaluateRealtime`; store at `alert_rule.go:395-403`
**Problem:** Every single `EvaluateRealtime` call (once per changed CVE) issues a fresh
`ListActiveRulesForEvaluation` bypass-transaction query that loads **all active non-EPSS-only rules across
all orgs** from the DB. During a feed page that changes K CVEs, that's K identical full-rule-set queries in
quick succession on the ingest thread. The compiled-rule *cache* (`cache.go`) avoids recompiling the DSL,
but the *rule list itself* (rows + `Conditions` JSON) is re-fetched and re-unmarshalled every time — the
cache is keyed by `(ruleID, dslVersion)` and only short-circuits `Compile`, not the list query nor the
`json.Unmarshal` of `rule.Conditions` in `loadAndCompileRule` on cache miss. There is no synchronized,
TTL'd shared snapshot of "the active rule set" that the whole ingest run could reuse. This compounds
finding #1: the per-CVE cost includes a full-table-ish rule scan, repeated.
**Impact:** Reachability: every changed CVE on the ingest path. Frequency: K times per page. Per-occurrence:
one all-org rule-list query + N `json.Unmarshal`/cache lookups. Aggregates badly under backfill.
**Confidence:** Strong-static (query is inside `EvaluateRealtime`, called per CVE).
**Effort:** Contained. If finding #1's decoupling (batch realtime eval per page) is done, the rule list is
naturally fetched once per page rather than per CVE — this finding largely dissolves into #1. If realtime
stays per-CVE, add a short-TTL shared rule snapshot (e.g. `sync.Once`-style refresh guarded by RWMutex,
invalidated on rule create/update/delete like the existing cache `Evict`) so the loop reuses one rule set.
Guard: the snapshot must be invalidated on the same events that call `RuleCache.Evict`, or newly-activated
rules would be missed within the TTL window — note this is a correctness edge, verify against activation
tests before shipping a TTL.
**Verification plan:** Count queries: serial-per-CVE issues K list queries per K-CVE page; cached-per-page
issues 1. Bench a K=100 page. Correctness guard: a test that activates a rule mid-ingest and asserts it is
picked up within the snapshot TTL (or immediately if invalidation is wired), plus existing realtime tests.

---

### [MINOR] Regex post-filter over up to 5,000 candidates runs single-threaded; parallelizable but bounded and CPU-cheap relative to the SQL it follows

**Location:** `internal/alert/dsl/postfilter.go:12-23` (`ApplyPostFilters`), invoked from `evaluator.go:420`
and `dsl_executor.go:201-211`
**Problem:** The lane prompt flags the 5,000-candidate regex postfilter as a parallelization candidate.
`ApplyPostFilters` is a serial `for _, c := range candidates` applying compiled `*regexp.Regexp.MatchString`
per candidate per filter. It is correctly structured otherwise — patterns are **compiled once** at rule
compile time and cached (`CompiledRule`, not recompiled per candidate; the Go-pack "regexp.Compile in a
loop" footgun is *absent* here), and the matcher reads only from the immutable candidate slice with no
shared mutable state, so it is trivially data-parallel. However: n is hard-capped at `candidateCap = 5000`
(`evaluator.go:514-516` fails closed beyond that), `MatchString` on a pre-lowercased description is
microseconds, and this work runs *after* a DB round-trip that fetched those 5,000 rows — the SQL dominates.
Parallelizing a provably-bounded ≤5,000-element CPU loop that trails a network round-trip is a
readability-for-unmeasured-gain trade the calibration section warns against. **Reporting as MINOR / likely
not-a-finding**: the durable win here is parallelizing the *rules* (findings #1, #2), which gets the regex
work concurrent for free across rules, not sharding within a single rule's candidate slice.
**Impact:** Reachability: every rule with ≥1 regex postfilter. Frequency: per-eval. Per-occurrence:
≤5,000 × `MatchString`, CPU-only, bounded. Small absolute cost, dominated by the preceding SQL.
**Confidence:** Strong-static (bounded n, patterns precompiled).
**Effort:** Localized if pursued (slice into G chunks, `errgroup`, append under mutex or per-chunk result
slices merged) — but **recommend not pursuing** standalone; subsume into rule-level parallelism.
**Verification plan:** If ever measured to matter (profile shows regex hot), chunk the candidate slice and
merge per-chunk matches preserving no required order (`ApplyPostFilters` result order is not relied on for
correctness — `InsertAlertEvent` is keyed by cve_id). Correctness guard: `postfilter_test.go` AND/OR/negate
cases must stay green; order-independence must be asserted before chunking.

---

### [MINOR] Channel fan-out per match is serial and holds the eval flow; pool-exhaustion guard needed before any eval parallelization

**Location:** `internal/notify/dispatcher.go:62-72` (`Fanout` channel loop), called per match at
`evaluator.go:440-445`; pool sizing `config.go:20` (`DB_MAX_CONNS=25`)
**Problem (DEFEND, two parts):**
(a) `Fanout` loops bound channels serially calling `UpsertDelivery` (one DB write each). It is invoked
*inside* the per-match loop in `evaluateRule` (`:436-445`), so for a rule that matches M CVEs with C
channels, the eval thread does M×C serial delivery upserts before returning — all on the realtime/ingest
critical path. This is correctly *not* doing the outbound webhook HTTP call inline (that's the delivery
worker's job, per the dispatcher contract), so the per-channel cost is a DB upsert, not a network call —
which keeps it MINOR. But it still serializes M×C writes onto the hot path.
(b) **Pool-exhaustion guard for findings #1/#2:** the pgxpool is `DB_MAX_CONNS=25`, shared by ingest, the
API, the delivery worker, and the evaluator. Every `evaluateRule` opens a `bypassTx` connection
(`evaluator.go:551`), and every `InsertAlertEvent`/`Fanout.UpsertDelivery`/`InsertAlertRuleRun` opens
*its own* `withBypassTx` connection (`alert_rule.go`). If the rule loop (finding #1 or #2) is fanned out
with `go`/`errgroup` **without** `SetLimit`, each concurrent rule + its nested per-match inserts can each
grab a connection, and the fan-out trivially exceeds 25 → callers block on pool acquisition or time out.
**Any parallelization of the rule loop MUST cap concurrency well below the pool size and account for the
fact that each rule transitively opens multiple short-lived connections (eval tx, then a separate tx per
matched event, per run-row).** Unbounded `go f()` over rules is the exact "unbounded goroutine spawn /
pool exhaustion" footgun the lane is told to defend against.
**Impact:** (a) M×C serial upserts on the eval path — minor at typical M, C. (b) Latent: becomes a CRITICAL
correctness/throughput regression the moment findings #1/#2 are implemented naively. Recording as the
mandatory correctness guard attached to the EXPLOIT findings.
**Confidence:** Strong-static (pool size in config; per-call `withBypassTx` opens a connection each).
**Effort:** Localized (use `errgroup.SetLimit(n)` with n ≤ ~8 and verify n×(connections-per-rule) < 25 −
headroom). Optionally batch `InsertAlertEvent` into a multi-row insert to cut connection churn per match.
**Verification plan:** Count connections: serial path = 1 in flight; naive fan-out = up to R×(1+matches)
in flight. Assert chosen `SetLimit` × max-connections-per-rule ≤ pool budget. Correctness guard: an
integration test that runs a parallel sweep against `SeedCorpus` with `DB_MAX_CONNS` set low (e.g. 5) and
asserts no pool-timeout errors and identical `alert_events` output vs the serial run.

---

## Suspected Bugs (for follow-up)

- **`evaluator.go:97-115` (realtime) `totalMatches`/run-row accounting is per-rule serial today** — *not a
  bug as written*, but flagged because finding #1/#2 parallelization would make `totalMatches += matchCount`
  (`:107`, `:212`) a data race if done naively. Pre-emptive note for whoever implements the EXPLOIT: convert
  to atomic or per-goroutine-sum-at-join. Not a current correctness defect.
- **`evaluator.go:414`, `:463` `candidatesEval` returns `len(candidateIDs)` (input count), not the number
  of rows actually scanned post-SQL-filter** — already recorded by the memory lane
  (`2026-06-05-s2-alert-memory.md`). Metrics-correctness discrepancy in `alert_rule_runs.candidates_evaluated`,
  not a perf issue. Not chased.
- **`evaluator.go:449-461` resolution detection builds `candidateSet` from `candidateIDs`** inside the
  per-rule path; under rule-loop parallelization this is per-goroutine local (safe), but the
  `GetUnresolvedAlertEventCVEs` read + `ResolveAlertEvent` write pair (`:426`, `:456`) is not transactionally
  atomic with the match inserts — a concurrent realtime eval of the same rule (if #1 enqueues per-CVE jobs
  that race) could interleave resolve/insert. The existing serial design avoids this; any move to concurrent
  *same-rule* evaluation must re-examine resolution-detection atomicity. Recording, not chasing.
