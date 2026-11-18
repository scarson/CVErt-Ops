# S6 Reports / AI / retention — concurrency & parallelization lane

ABOUTME: Performance audit (concurrency lane) for the reports, AI-orchestration, and retention slice.
ABOUTME: Both directions — exploitable serialization to parallelize, and concurrency hazards to defend.

Auditor lane: **concurrency** (S6, reduced/warm). No runtime profiling available — all findings are
static. Scope read in full: `internal/ai/**`, `internal/retention/**`,
`internal/store/{scheduled_report,ai,retention}.go`, `internal/api/{reports,ai}.go`, plus the actual
report-generation path in `internal/notify/{digest,worker}.go` and the worker-pool concurrency model
in `internal/worker/pool.go` (the report CRUD handlers in `api/reports.go` do not generate reports;
generation lives in the notify worker).

---

### [MAJOR] Digest generation runs inline on the worker select-loop goroutine, serializing every other worker ticker behind it

**Location:** `internal/notify/worker.go:105-106` (`case <-digestTicker.C: w.runDigest(ctx)`) →
`internal/notify/digest.go:87-98` (`runDigest`)

**Problem:** `runDigest` is invoked directly from the worker's single `select` loop, not dispatched to
the worker pool or a goroutine. It claims up to 10 due reports and processes them one at a time
(`for _, report := range reports`). Each `executeDigestReport` issues a serial chain of DB round-trips:
`DigestCVEs` (a scan of the shared corpus, up to 500 rows), `ListActiveChannelsForDigest`, one
`InsertDigestDelivery` **per channel**, then `AdvanceReport` — each its own `withBypassTx`
transaction. While this runs, the same goroutine cannot service `claimTicker` (5s — the actual
delivery dispatch loop), `stuckTicker`, `recoveryTicker`, or `retentionTicker`, because they are all
arms of the same `select`. The claim-loop health timestamp (`lastClaimAt`) is also not advanced
during a long digest pass, and `Healthy()` flips false after 10s (`worker.go:123`), so a slow digest
batch can mark the worker unhealthy for `/readyz`.

**Impact:** Reachable on every 60s digest tick whenever reports are due. Per-occurrence cost scales
with `reports × (2 + channels)` sequential DB transactions, all blocking the delivery hot path. At a
report-heavy minute (10 reports × several channels each) this is dozens of serial round-trips holding
the one loop goroutine — directly delaying outbound notification dispatch (the latency-sensitive
function of this worker). The file's own header comment ("synchronous ticker in the worker select
loop") confirms this is by design, but the design couples an unbounded-fan-out batch job to the
delivery dispatcher's heartbeat.

**Confidence:** Strong-static (control flow is explicit; `select` arms share one goroutine).

**Effort:** Contained — dispatch `runDigest` onto the existing worker pool as its own queue
(`p.RegisterWithConcurrency`), or run it in a tracked goroutine off the select loop (mirroring
`runClaim`'s `w.wg.Add(1); go func(){...}`). The per-report DB ops can stay serial; the goal is to
unblock the select loop, not parallelize generation. Requires care that two digest passes don't
overlap — `ClaimDueReports` already atomically claims (advances `next_run_at`), so an overlapping
tick claims a disjoint set; a lock_key/`HasPendingOrRunningJob` guard (as retention uses) makes it
explicit.

**Verification plan:** Argue from structure — count the transactions chained in `executeDigestReport`
(`DigestCVEs` + `ListActiveChannelsForDigest` + `len(channels)` × `InsertDigestDelivery` +
`AdvanceReport`), all on the loop goroutine. Correctness guard: existing `TestRunDigest*` /
`worker_test.go` digest tests must still pass (one claim → deliveries inserted → `next_run_at`
advanced); add a test asserting a digest pass does not stall a concurrent `runClaim` (e.g. that
`lastClaimAt` advances within the claim interval while a digest is in flight).

---

### [MAJOR] Independent per-report digest generation runs strictly sequentially — bound-parallelizable

**Location:** `internal/notify/digest.go:93-97` (`for _, report := range reports { w.executeDigestReport(...) }`)

**Problem:** Each claimed report is independent: different `report.ID`, different `org_id`, disjoint
channel sets, disjoint `notification_deliveries` rows (insert is `ON CONFLICT DO NOTHING` keyed by
report+channel). There is no shared mutable state across iterations and no ordering constraint. Yet
they are processed one fully-completed report at a time. The only shared input is the **global** CVE
corpus read by `DigestCVEs(since, severities)` — which is read-only and, notably, recomputed from
scratch for every report even when many reports share the same `(since, severity-threshold)` window
(see Suspected Bugs note on redundant corpus scans).

**Impact:** Reachable every digest tick with ≥2 due reports. Latency of a batch is the **sum** of
per-report latencies (corpus scan + channel list + N delivery inserts each) rather than roughly the
max. With a claim batch of 10 reports this is up to a ~10× wall-clock inflation of the digest pass,
which (per the finding above) is time the delivery loop is blocked. The work is I/O-bound DB round-
trips — exactly the shape that benefits from bounded fan-out.

**Confidence:** Strong-static (independence provable from the code: distinct orgs/reports, idempotent
inserts, read-only shared corpus).

**Effort:** Contained — wrap the loop body in a bounded `errgroup.Group` with `SetLimit(k)` or a
semaphore-gated `sync.WaitGroup`, sized small (e.g. 4–8) to cap pool connections consumed. Each
`executeDigestReport` already takes its own short-lived transactions, so concurrent execution is
connection-safe under pgxpool. Guard: must not exceed pgxpool `MaxConns`; pick `k` conservatively and
document it. (If the first finding is taken and digest moves to the worker pool with
`RegisterWithConcurrency`, this fan-out can be expressed as pool concurrency instead.)

**Verification plan:** Independence argument above is the justification; no fabricated speedup numbers.
Correctness guard: existing digest tests pin per-report behavior (deliveries inserted, `next_run_at`
advanced, `send_on_empty` honored). Add a test with multiple due reports across orgs asserting all
produce deliveries regardless of interleaving, and that the bounded limiter never opens more than `k`
concurrent transactions.

---

### [MINOR] Gemini client lazy-init holds a process-wide mutex across a 10s network dial; concurrent first callers serialize

**Location:** `internal/ai/gemini.go:40-57` (`getClient`)

**Problem:** `getClient` takes `g.mu.Lock()` and holds it for the entire `genai.NewClient` call, which
performs network setup with a 10s timeout (`gemini.go:46`). On a cold client, every concurrent
AI request (NL-search and summarize across all orgs share the one `GeminiClient`) blocks on this
mutex until the first dial completes or times out. After init the lock is held only briefly (nil
check), so this is a cold-start / post-failure-retry concern, not steady-state.

**Impact:** Reachable at startup and after any init failure (the code retries init on the next call).
Bounded blast radius: only the first dial window (≤10s). Per-occurrence cost is queueing of
concurrent AI requests behind one dial. Low aggregate cost because AI endpoints are low-QPS and
gated by quota, and the steady-state path is lock-free-ish (short critical section). Worth noting,
not worth a complex fix.

**Confidence:** Strong-static (lock scope is explicit).

**Effort:** Localized — use `sync.Once` for init (so failures don't poison, keep retry-on-error via a
reset) or double-checked init that releases the lock before dialing and re-acquires to store. Given
the low impact, leaving it is defensible.

**Verification plan:** Critical-section scope is visible in source. Guard: `gemini_internal_test.go`
init/retry tests must still pass (init failure on first call retried on second).

---

### [MINOR] `getClient` drops parent-context cancellation during init by deriving a fresh `context.WithTimeout(ctx, 10s)`

**Location:** `internal/ai/gemini.go:46` (`ctx, cancel := context.WithTimeout(ctx, 10*time.Second)`)

**Problem:** Init derives from the request context, so cancellation *does* propagate (good). But the
fixed 10s init budget is independent of the caller's own deadline — a request with, say, a 3s server
timeout can still spend up to 10s inside `NewClient` before the per-call `g.timeout` context
(`gemini.go:67`/`:111`) is even created. The outer request may have already been abandoned by the
HTTP layer. This is a timeout-budget-composition issue, not a leak (the parent cancel still fires).

**Impact:** Reachable only on cold init under a tight caller deadline; bounded to one 10s window. Minor:
wastes a worker/handler slot for up to 10s on an already-dead request. Aggregate cost low (cold path).

**Confidence:** Heuristic (depends on caller deadlines, which aren't fixed here).

**Effort:** Localized — clamp init timeout to `min(10s, remaining(ctx))`, or just honor the caller's
deadline. Low priority.

**Verification plan:** Reason from the two stacked timeouts (init 10s, then call `g.timeout`). Guard:
existing timeout test in `gemini_internal_test.go` continues to pass.

---

### DEFEND — checks that PASSED (recorded so they aren't re-flagged)

These were specifically examined for the listed concurrency hazards and found correct:

- **AI quota check is NOT under a global lock.** `IncrementAIUsage` (`store/ai.go:44`) uses a per-org
  `withOrgTx` — a single atomic UPSERT-and-return-count, scoped to one org row. No process-wide mutex
  or serialized transaction on the request path. The check-then-act is intentionally increment-first
  (`api/ai.go:121`,`:306`) so it is race-free without a lock, and over-count is corrected by
  `DecrementAIUsage` on LLM failure.
- **No DB transaction is held across the external Gemini HTTP call.** Both handlers do quota TX →
  commit → `srv.llm.*` call → separate token-update/cache-write TXs (`api/ai.go:121-168`,
  `:306-356`). The blocking external call holds no pooled connection. This is the correct claim →
  commit → call → new-TX shape.
- **No transaction spans report generation.** `executeDigestReport` uses discrete short-lived
  `withBypassTx` calls per step; nothing holds a connection across the whole report. (The cost is the
  *number* of serial TXs, per the MAJOR findings — not lock duration.)
- **Retention DELETEs are bounded-batch and do not hold long locks.** `cleanupTable`
  (`retention/runner.go:169-200`) loops `DELETE ... LIMIT batchSize` in separate transactions with a
  runtime deadline and per-iteration `ctx.Err()` check, so writers are not blocked by a single large
  DELETE. Tier-gated tables group orgs by retention window and DELETE with `org_id = ANY($orgIDs)` —
  correctly batched. Running the tables serially within one runtime budget is the intended design
  (single background job, lock_key-guarded against overlap via `HasPendingOrRunningJob`,
  `worker.go:442`), not an exploitable serialization: parallelizing table passes would contend on the
  same pool/deadline for no latency requirement (retention is not latency-sensitive). **Not a
  finding.**
- **Retention job cannot overlap itself.** `scheduleRetention` (`worker.go:437-459`) checks
  `HasPendingOrRunningJob("cleanup:retention")` and enqueues with `lock_key`, so concurrent retention
  runs (which would multiply lock contention) cannot happen.
- **No goroutine leaks found in this slice.** Digest/retention run inline (no spawned goroutines to
  leak); the AI client spawns none. The delivery fan-out (`runClaim`, `worker.go:167-177`) uses a
  tracked `sync.WaitGroup` + bounded per-org semaphore with `context.WithoutCancel` for graceful
  drain — out of this slice's scope but adjacent and correct.

---

## Suspected Bugs (for follow-up)

- **`report.AiSummary` is never honored — the AI summarizer is not wired into the digest path.**
  `internal/notify/digest.go` builds the digest payload (`cveSnapshot` array) and inserts deliveries
  with **no** call to `srv.llm.Summarize`, and the email render path (`worker.go:302-327`,
  `RenderDigest`) never invokes the LLM. The `ai_summary` boolean is stored and round-tripped through
  CRUD (`api/reports.go:159,325`; `store/scheduled_report.go`) but has no effect on generated output.
  Either the feature is unimplemented or the flag is dead. (Recorded only — not chased. It is *also*
  relevant to my lane in that, if/when AI summaries ARE added to digests, the per-report serial loop
  in `digest.go:93` would then issue blocking external LLM calls inline on the worker select-loop
  goroutine — the MAJOR findings above would escalate from "serial DB round-trips" to "serial network
  round-trips blocking delivery dispatch." Design the summary fan-out off the select loop from the
  start.)

- **Redundant full-corpus scans across reports sharing a digest window.** `DigestCVEs(since,
  severities)` (`digest.go:121`) reads the global CVE corpus once per report. Many reports will share
  the same `(since-bucket, severity-threshold)` and could share one scan result, but `since` is
  per-report (`COALESCE(last_run_at, created_at)`), so de-duplication is non-trivial. Borderline
  performance (redundant work) rather than a correctness bug; noted for the data-access lane.
