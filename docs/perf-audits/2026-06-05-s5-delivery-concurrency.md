# S5 — Async delivery & per-request overhead — concurrency & parallelization lane

Date: 2026-06-05
Lane: concurrency & parallelization (both directions: exploit + defend)
Scope: `internal/notify/**`, `internal/worker/**`, `internal/secure/**`,
`internal/store/{notification_delivery,jobs,security_events}.go`,
`internal/api/{deliveries,channels,ratelimit,scim_ratelimit,lockout,admin_deliveries,admin_security_events}.go`
Runtime profiling: unavailable (no Docker/testcontainers). No `Measured` confidence used.

## Hot-path facts verified

- **No DB tx held across an outbound webhook.** `deliver()` (worker.go:180) does
  `GetNotificationChannelForDelivery` (own tx) → `Send()` HTTP → `CompleteDelivery`/`RetryDelivery`
  (separate tx). The webhook HTTP call is never inside a `withBypassTx` closure. Policy holds.
- **Fan-out uses `sync.WaitGroup`, not `errgroup`.** `runClaim` (worker.go:167-177) adds to `w.wg`
  per row; security writer (writer.go:96) and worker pool (pool.go) all use `sync.WaitGroup` /
  `inflight.Wait()`. No `errgroup` anywhere in the lane. Policy holds — per-channel errors are
  isolated (each `deliver` records its own status; one failure never cancels siblings).
- **Security-event channel does NOT block the request path.** `EventWriter.Write` (writer.go:83-91)
  uses a non-blocking `select` with `default` → drops on full `sem` (capacity 50). Backpressure
  drops, never blocks. Correct.
- **IP rate limiter is auth-only, not every request.** `authRateLimit()` is mounted on ~9 auth
  routes (server.go:243-254) and `checkAuthRateLimit` is called only in auth handlers. The global
  mutex in `ipRateLimiter.Allow` (ratelimit.go:46) is therefore NOT on the general hot path — the
  lane hint "rate-limit check on every request" does not hold for this codebase. Not a finding.
- **No goroutine leaks.** Every `go` is bounded: delivery by per-org sem (worker.go:170), security
  writes by `sem` cap 50 (writer.go:84), worker pool by per-queue sem (pool.go:150). Eviction
  goroutines are stoppable (`Stop()` closes `done`).

---

## Findings

### [MAJOR] Worker pool claims at most one job per 2 s poll tick — concurrency slots ramp up serially, not in parallel
**Location:** `internal/worker/pool.go:158-179` (`runQueue`)
**Problem:** Each queue goroutine has a per-queue semaphore of size `maxConc`, but the poll loop
fires `ticker.C` every `pollInterval = 2s` and on each tick starts **exactly one** goroutine that
claims **one** job (`processOne` → `ClaimJob` claims a single row). So a queue registered with
concurrency N that suddenly has a backlog of N ready jobs takes N ticks — `N × 2s` — to reach full
parallelism, and steady-state throughput per queue is capped at one job started per 2 s regardless
of how many concurrency slots are free. The "concurrency" knob only bounds the *ceiling*; it never
accelerates drain of a backlog because new work is admitted one-per-tick. A queue with concurrency
8 and 8 instantly-available jobs runs effectively serially for the first 16 s.
**Impact:** Reachable on every queue that registers concurrency > 1 (the whole point of
`RegisterWithConcurrency`). Frequency: every backlog/burst (feed ingest, alert scans, retention).
Per-occurrence: backlog drain latency inflated by `(slots-1) × 2s`; sustained throughput capped at
0.5 jobs/s/queue even with idle slots and idle DB pool. Contrast: the *delivery* worker
(`runClaim`, worker.go:152) claims a **batch** of 50 and fans them all out at once — that path does
not have this defect, which is exactly the pattern the job pool is missing.
**Confidence:** Strong-static (loop structure admits one job per tick; `ClaimJob` is `:one`).
**Effort:** Contained — drain the semaphore in an inner loop on each tick (claim until a slot can't
be filled or `ClaimJob` returns nil), or claim a batch like the delivery worker. One function plus
its tick cadence; no signature change.
**Verification plan:** Argue: with C free slots and ≥C ready rows, current code admits 1/tick →
C ticks to saturate; inner-claim-loop admits min(C, ready)/tick → 1 tick to saturate. No allocation
change. Correctness guard: a test that enqueues K > concurrency jobs and asserts all are claimed
within a single tick window (not K ticks), plus the existing stale-recovery/`processOne` panic
tests stay green.

### [MAJOR] Webhook client never sets `MaxIdleConnsPerHost` — keep-alive pool defaults to 2, forcing TCP+TLS re-dial under concurrent fan-out
**Location:** `internal/notify/client.go:23-25` (`BuildSafeClient`)
**Problem:** The Transport sets `MaxConnsPerHost = 50` (the ceiling) but leaves
`MaxIdleConnsPerHost` at the stdlib default of **2**. After a burst of concurrent deliveries to the
same webhook host, at most 2 idle connections are retained; the other ~48 are closed immediately
after each request returns. The very next delivery batch to that host must re-establish TCP + full
TLS handshake for connections 3..50. The whole point of capping `MaxConnsPerHost` at 50 (per the
file's own comment, "under alert load") is the concurrent-fan-out case — exactly where idle-conn
starvation bites. A single org commonly routes many rules to one webhook endpoint (one Slack/PagerDuty
host), so per-host concurrency is high and re-dial cost (TLS handshake ≈ 1-2 RTT + asymmetric crypto)
is paid repeatedly.
**Impact:** Reachable on every multi-delivery burst to a shared webhook host (the common alert-storm
shape). Per-occurrence: a TLS handshake per non-reused connection instead of an HTTP round-trip on a
warm conn — dominates the 10 s-budget request when the remote is fast. Aggregate: O(deliveries −
2 per host) extra handshakes per burst.
**Confidence:** Strong-static (default `MaxIdleConnsPerHost = DefaultMaxIdleConnsPerHost` is 2 unless
set; only `MaxConnsPerHost` is overridden here).
**Effort:** Localized — set `t.MaxIdleConnsPerHost = t.MaxConnsPerHost` (and confirm `IdleConnTimeout`)
next to the existing line. One function.
**Verification plan:** Argue idle-pool size 2 → ≥48 re-dials per 50-wide burst to one host; setting it
to 50 → 0 re-dials within the burst. Correctness guard: existing `webhook_test.go:281` Transport
assertion extended to also assert `MaxIdleConnsPerHost == 50`; the body-drain reuse test
(see related MINOR) stays green.

### [MINOR] Webhook response body drained only to 4 KiB — bodies larger than 4 KiB poison connection reuse
**Location:** `internal/notify/webhook.go:78`
**Problem:** `io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))` caps the drain at 4 KiB. The
comment says this is "to allow connection reuse," but the opposite is true when the response body
exceeds 4 KiB: `net/http` only returns a connection to the idle pool if the body is read to EOF
before `Close()`. With unread bytes remaining, `resp.Body.Close()` closes the underlying connection
instead of reusing it. Webhook receivers that echo the request or return verbose JSON (>4 KiB)
therefore defeat keep-alive on every delivery, compounding finding #2.
**Impact:** Reachable only for webhook targets that return >4 KiB responses (receiver-dependent).
Per-occurrence: one extra connection teardown + re-dial on the next delivery to that host. Bounded
but interacts multiplicatively with the idle-conn finding.
**Confidence:** Heuristic (depends on remote response sizes; the reuse-vs-close rule is `net/http`
behavior, certain).
**Effort:** Localized — drain to a larger sentinel before `Close` (`io.Copy(io.Discard, resp.Body)`
with the existing safeurl size guard, or a much higher limit). One line.
**Verification plan:** Argue: unread body → conn not pooled; full drain → pooled. Correctness guard:
a test posting to an httptest server returning a >4 KiB body and asserting the connection is reused
on a second request (e.g. via `httptrace.GotConn{Reused:true}`).

### [MINOR] Email delivery path issues per-row metadata lookups (rule name / report name / org name) with no per-batch memoization
**Location:** `internal/notify/worker.go:284-312` (`deliverEmail`)
**Problem:** For each claimed email delivery, the worker re-queries `GetAlertRuleName` (alert kind)
or `GetScheduledReportName` + `GetOrgByID` (digest kind) — one to two extra DB round-trips per row,
on top of the per-row `GetNotificationChannelForDelivery`. A claim batch is 50 rows
(`NOTIFY_CLAIM_BATCH_SIZE=50`). When many rows share the same rule/report/org (the normal case —
one noisy rule fans to several email channels, or a digest run inserts one delivery per channel for
the same report+org), these are redundant identical lookups that could be memoized within the batch.
The lookups run concurrently across the 50 in-flight goroutines, so they also spike demand on the
25-conn DB pool (finding #5).
**Impact:** Reachable on every email-channel delivery batch. Per-occurrence: 1-2 redundant queries ×
(rows sharing a key − 1). Bounded by batch size (≤50) but recurs every 5 s claim tick under load.
**Confidence:** Strong-static (queries are unconditional per row; no cache).
**Effort:** Contained — a per-`runClaim` map (rule_id→name, report_id→name, org_id→name) threaded
into `deliver`, or a batch pre-fetch. Touches `runClaim` + `deliver`/`deliverEmail` signatures.
**Verification plan:** Argue N rows sharing a key → N lookups now vs 1 memoized. Correctness guard:
existing email render tests stay green; add a counter assertion that K deliveries for one rule
issue one rule-name query.

### [MINOR] Up to 50 concurrent deliveries contend for a 25-connection DB pool at their commit/lookup boundaries
**Location:** `internal/notify/worker.go:152-177` (`runClaim` batch=50) vs
`internal/config/config.go:20` (`DB_MAX_CONNS=25`), `MaxConcurrentPerOrg=5`
**Problem:** `runClaim` fans the full claim batch (default 50) into goroutines bounded only by
*per-org* semaphores (5 each). With deliveries spread across ≥10 orgs, up to 50 deliveries run
concurrently. Each `deliver` acquires and releases a pool connection several times
(channel lookup → [HTTP] → complete/retry; email adds rule/org lookups). At the lookup and
completion boundaries, demand can momentarily reach ~50 connection checkouts against a 25-conn pool,
so roughly half the deliveries block in `pgxpool.Acquire` waiting for a connection. The HTTP call
itself correctly holds no connection, so this is bounded and transient — but it caps effective
delivery parallelism at the DB-pool ceiling, not the configured `ClaimBatchSize`.
**Impact:** Reachable when batch parallelism (orgs × 5) exceeds 25. Per-occurrence: pool-acquire
wait at each DB boundary; no deadlock (connections are short-held). Mostly a sizing-coherence issue.
**Confidence:** Heuristic (depends on org spread within a batch and pool saturation from other
subsystems sharing the same 25-conn pool).
**Effort:** Localized config/doc coherence — cap effective delivery concurrency to a fraction of the
pool, or document that `ClaimBatchSize × peak-org-spread` should track `DB_MAX_CONNS`. No structural
change required.
**Verification plan:** Argue 50 concurrent × (checkout per DB op) > 25 → acquire waits. No fabricated
numbers. Correctness guard: none needed (behavior unchanged; this is a sizing remark).

### [MINOR] `Dispatcher.Fanout` upserts deliveries serially, each in its own transaction
**Location:** `internal/notify/dispatcher.go:62-72`
**Problem:** Fanout loops over channels and calls `UpsertDelivery` once per channel; each call opens
its own `withBypassRawTx` transaction (notification_delivery.go:40). For a rule bound to K channels
this is K sequential round-trips (BEGIN/INSERT…ON CONFLICT/COMMIT each). This runs on the realtime
alert path (fires on CVE upsert when `material_hash` changes) and in the recovery scanner
(worker.go:430, up to 100 orphans × K channels each, fully serial). K is typically small, so this is
a minor constant factor, but a single multi-statement upsert (or one tx wrapping all K upserts) would
cut transaction overhead proportionally on the hot upsert path.
**Impact:** Reachable on every realtime fan-out and every recovery tick. Per-occurrence: K tx
round-trips instead of 1. K bounded by channels-per-rule (small).
**Confidence:** Strong-static (loop + per-call tx is explicit).
**Effort:** Contained — wrap the loop in one `withBypassRawTx` and exec K statements on one conn,
or a single multi-row upsert. Touches `Fanout` + a new batch store method.
**Verification plan:** Argue K tx → 1 tx. Correctness guard: existing fanout idempotency test
(ON CONFLICT debounce append) stays green; the per-channel-error-isolation behavior must be
preserved (a single failing channel upsert must not abort the others — current code logs and
continues, so a batch tx must not roll back all K on one conflict-free failure; if isolation can't be
preserved in one tx, keep separate txs but pipeline them).

---

## Suspected Bugs (for follow-up)

- **`evictStaleSemaphores` reads `len(w.sems[orgID])` to decide eviction (worker.go:408).** A
  per-org semaphore is a buffered channel; `len()==0` means "no slots currently held," but a
  delivery goroutine could acquire the slot immediately after the check, after which the map entry
  is deleted and `semaphore()` lazily recreates a *fresh* channel for the same org. Two channels
  briefly coexist for one org, transiently allowing up to `2 × MaxConcurrentPerOrg` concurrent
  deliveries for that org. Not a slowness issue; flagged for correctness follow-up. (file: worker.go:403-413)
- **`backoffSeconds` computes `base * 2^(attempt-1)` with no cap (worker.go:384-389).** With a large
  `MaxAttempts`, the delay can overflow `int` / schedule absurdly distant retries. Bounded by
  `MaxAttempts` config; flagged, not chased. (file: worker.go:384)
