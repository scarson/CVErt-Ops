# S2 Alert Evaluation Engine — Lane: framework-idiom currency

**Date:** 2026-06-05
**Slice:** S2 "Alert evaluation engine" (FULL, HOT)
**Lane:** idiom-currency (framework / stdlib idiom freshness vs Go 1.26)
**Sources read (actual code):**
`internal/alert/{cache,evaluator}.go`, `internal/alert/dsl/{compiler,types,field,parser,validator,accessor,postfilter}.go`,
`internal/store/{alert_rule,dsl_executor,alert_rule_channel}.go`

**Version basis:** project is **Go 1.26.2** (`go.mod`); squirrel `v1.5.4`. The version index
(`version-indexes/go.md`) is `covered_through: Go 1.24`. Go 1.26 is **past** the index's coverage,
so any claim resting on a 1.25/1.26-specific feature is **Heuristic** (no fabrication) per lane
rules. Claims grounded in features at/below 1.24 (slices, maps, swiss-map, sync.Map hash-trie) cite
the index entry and are **Strong-static** for currency purposes.

The CVE corpus is global/shared; the hot loop is the realtime path (`EvaluateRealtime` fires on every
CVE upsert) and the batch/EPSS paths (periodic, but iterate the whole modified window × every active
rule across all orgs). PostFilter regex evaluation runs in-process per-candidate-per-rule.

---

## Findings

### [MINOR] `containsStr` linear-scan helper duplicates the stdlib `slices.Contains` fast path
**Location:** `internal/alert/dsl/validator.go:224-231` (`containsStr`), call sites at
`validator.go:60` (`spec.validOps`), `149`, `160`, `205`, `216` (enum value checks)
**Problem:** `containsStr` is a hand-rolled `for _, v := range slice { if v == s }` linear membership
test. Go 1.21 added `slices.Contains` (version index, *Stdlib & Generics* → "`slices` package"),
which is the current idiom and is generically specialised by the compiler. The hand-rolled helper is
a superseded idiom. There is no measurable per-call win — both are O(n) over tiny fixed slices
(`validOps` ≤ 7, enum sets ≤ 12) — so the impact is **currency/maintainability only**, not a hot-path
cost. Validation runs on rule create/update (cold), not in the evaluation loop, so even the
aggregate cost is negligible. Flagging strictly as a superseded-idiom currency note, not a perf win.
**Impact:** Cold path (rule mutation only); n ≤ 12; zero aggregate runtime impact. Pure idiom drift.
**Confidence:** Strong-static (the idiom is unambiguously superseded by `slices.Contains` since 1.21;
freshness is below `covered_through` 1.24).
**Effort:** Localized — replace one helper + 5 call sites; delete `containsStr`.
**Verification plan:** `slices.Contains(spec.validOps, c.Op)` is a drop-in for `containsStr(...)`;
no behavioral change (both report exact-equality membership). Existing `dsl_test.go` validator cases
pin behavior. No allocation/complexity argument needed — this is a readability/currency change with
no claimed throughput gain.

---

### [MINOR] `cveColumns` and the squirrel builder rebuilt per `ExecuteDSLQuery`/`queryCandidates` call instead of leaning on prepared statements
**Location:** `internal/store/dsl_executor.go:121-161` (`ExecuteDSLQuery`),
`internal/alert/evaluator.go:470-495` (`queryCandidates`)
**Problem:** Each call constructs a fresh `sq.StatementBuilder.PlaceholderFormat(...)`, re-selects the
20-column `cveColumns` list, appends joins/where, and calls `ToSql()` to render a query string that
is then sent to the driver. The profile-pack `data-access` lens names "missing prepared statements
for queries executed in tight loops or under concurrent load" — and the evaluator runs this builder
once **per rule per batch** (and per candidate page on the activation path). Because the project pins
`DefaultQueryExecMode = QueryExecModeSimpleProtocol` for PgBouncer transaction-mode compatibility
(noted in CLAUDE.md), pgx does **not** cache prepared statements server-side, so every distinct
rendered SQL string is parsed+planned afresh by Postgres. squirrel necessarily produces a *different*
SQL string per rule shape, so true server-side statement caching is not available here regardless —
this is an architectural constraint, not a fixable idiom, and squirrel-vs-prepared is the documented
project choice for dynamic DSL. **No version-superseded API applies** (squirrel v1.5.4 is current and
the simple-protocol mode is deliberate). I record this only to close the lens item: the
prepared-statement fast path is intentionally bypassed and there is no newer idiom to adopt. **Not a
recommended change.**
**Impact:** Builder allocation is small relative to the DB round-trip it precedes; reachable on every
batch rule but dominated by the query itself. Negligible aggregate idiom cost.
**Confidence:** Heuristic (the simple-protocol interaction with statement caching depends on runtime
pgx/PgBouncer config not observable statically; conclusion is "no idiom fix available").
**Effort:** N/A — no change recommended.
**Verification plan:** None — this is a "lens item closed, no action" entry. The squirrel-per-call
pattern is the project's sanctioned dynamic-DSL approach; statement caching is foreclosed by the
deliberate `QueryExecModeSimpleProtocol` setting, not by a stale idiom.

---

### [MINOR] `RuleCache` uses `map`+`sync.RWMutex`; `Evict` does a full `range`-delete scan — current idiom, but note the sharding/`maps` alternatives for currency
**Location:** `internal/alert/cache.go:20-54`
**Problem:** The compiled-rule cache is `map[cacheKey]*dsl.CompiledRule` guarded by a `sync.RWMutex`.
`Evict(ruleID)` iterates the *entire* map deleting every `cacheKey` whose `ruleID` matches
(`cache.go:49-53`) because the key is `(ruleID, dslVersion)` and eviction is by `ruleID` only. Per
the version index (*Maps & Data Structures* → "`sync.Map`"), `map`+`RWMutex` is the **correct** choice
for this workload shape: reads dominate (every evaluation calls `Get`), writes happen on compile-miss,
and eviction is rare (rule update/delete). `sync.Map` would *not* improve this — it is tuned for
write-once/read-many but loses on the `Range`-style full eviction and adds interface-boxing on the
value. So the mutex-map is current and appropriate; flagging it only to record that the lens item was
examined and the idiom is **not** stale. The one genuine micro-currency note: `Evict`'s O(n)
range-delete could be avoided by keying on `ruleID` with a `map[ruleID]map[version]*CompiledRule`,
but n = number of cached rules is bounded by active rules and eviction is cold, so this is below the
calibration floor (provably bounded small n, cold path). **No change recommended.**
**Impact:** `Get` is the hot call (per rule per evaluation) and is already a single map lookup under
RLock — optimal. `Evict` is cold and O(cached-rules); bounded. No aggregate cost.
**Confidence:** Strong-static (workload shape is visible in the code; `map`+`RWMutex` is the indexed
recommendation for read-heavy/rare-write caches).
**Effort:** N/A — no change recommended.
**Verification plan:** None — lens item closed, idiom confirmed current.

---

## Summary

No CRITICAL or MAJOR idiom-currency findings. The S2 alert engine is written in current-Go style:

- **Regex compile-once is correctly done.** `dsl.Compile` compiles each regex pattern once at
  rule-compile time (`compiler.go:43-47`) and stores the `*regexp.Regexp` on `PostFilter.Pattern`;
  `matchesPostFilters` reuses it via `f.Pattern.MatchString` (`postfilter.go:27`). The compiled rule
  is cached (`RuleCache`), so the regex is **not** recompiled per evaluation — the classic
  `regexp.Compile`-in-a-loop footgun (profile-pack `algorithmic` item) is **absent**. This is the
  single most important thing to get right for a rule engine and it is correct. (One unverifiable
  remark for the bug section: RE2 is the right tool only where the field truly needs regex; the
  validator already steers cheap shapes toward `contains`/`starts_with` SQL ILIKE, so the prefilter
  discipline is in place.)
- **`ApplyPostFilters` uses generics** (`postfilter.go:12`, type-parameterised over
  `PostFilterTarget`) — the current generic-collection idiom, shared cleanly between the evaluator
  (`cveSummary`) and the store executor (`cvePostFilterTarget`). No reflection, no `interface{}`
  boxing in the match loop.
- **No `sort.Slice` / `errgroup` in scope.** The lane brief flagged `sort.Slice`→`slices.Sort` and
  the errgroup policy: neither `sort.Slice` nor `errgroup` appears anywhere in the S2 alert source.
  Ordering is done in SQL (`ORDER BY cve_id ASC` / `date_modified_canonical DESC`), and fan-out
  (`Dispatcher.Fanout`) is delegated to `internal/notify` (out of this slice), so the
  "errgroup-forbidden-for-notification-fan-out" policy is not violated in alert code — there is no
  goroutine fan-out here at all.
- **No `sync.Once`/`sync.Map` misuse.** The rule cache deliberately uses `map`+`RWMutex`, which the
  version index endorses for this read-heavy/rare-evict shape.

The only actionable item is the `containsStr` → `slices.Contains` swap (MINOR, cold path, pure
currency). The remaining two entries are "lens items examined, idiom confirmed current, no change."

---

## Suspected Bugs (for follow-up)

Recorded, not chased (per lane rules):

1. **Realtime path issues one candidate query per rule per CVE upsert** —
   `evaluator.go:96-115` (`EvaluateRealtime`) loops every active non-EPSS rule and calls
   `evaluateRule` → `queryCandidates` (`evaluator.go:470`), each opening its own `bypassTx` and
   running a separate `SELECT ... WHERE cve_id = ANY($candidateIDs)` for a **single** CVE. With N
   active rules across all orgs, a single CVE upsert triggers N transactions + N round-trips. This is
   a data-access/algorithmic concern (N+1-shaped), **out of the idiom-currency lane** — flagged here
   for the data-access lane. Not a correctness bug per se, but a throughput cliff as rule count grows.

2. **`EvaluateBatch`/`EvaluateEPSS` accumulate every candidate ID for the whole window into one
   in-memory `allCandidateIDs` slice** — `evaluator.go:172-193`. `append` grows without a
   preallocated cap, and the slice then feeds a `cve_id = ANY(?)` against `pq.Array` per rule. For a
   large modified window this is unbounded memory + a very large array parameter. Memory/data-access
   lane concern, not idiom-currency. Recorded only.

3. **`PostFilterField` re-lowercases `DescriptionPrimary` on every regex match** —
   `dsl_executor.go:273` calls `strings.ToLower(...)` inside `PostFilterField`, which is invoked once
   per filter per candidate. The evaluator's `cveSummary` path pre-lowercases in SQL
   (`COALESCE(lower(cves.description_primary), '')`, `evaluator.go:483`) and stores the result, so the
   store path's per-call `ToLower` is redundant repeated work when multiple regex filters hit the same
   row. Memory/algorithmic lane (recompute-in-loop), not idiom-currency. Recorded only.
