---
run_schema_version: 1
run_id: 2026-06-05-s5-delivery
date: 2026-06-05T02:05:00Z
scope: "S5 — Async delivery & per-request overhead (internal/{notify,worker,secure}/**, delivery/channel/job/security-event stores + handlers)"
methodology: { skill: performance-audit-cycle, plugin_version: "superpowers-plus@0.2.0 (vendored; version per source repo)" }
dispatch: { model_requested: "opus (latest; Claude Code Agent tool)", reasoning_effort: "default (harness exposes no knob)", overridden_by_user: false }
stack:
  - { ecosystem: go, framework: "doyensec/safeurl + net/http", version: "0.2.2" }
  - { ecosystem: go, framework: "stdlib+pgx", version: "go1.26.2 / pgx5.9.2" }
currency_briefs:
  - { framework: go, researched_on: null, status: "version-index go.md (covered_through 1.24); project on 1.26 — idiom Heuristic" }
lanes_run: [algorithmic, memory, data-access, concurrency]
lanes_skipped: { idiom-currency: "REDUCED tier — no distinct framework-idiom surface beyond what FULL slices covered", payload-startup: "n/a", cost-map: "REDUCED tier — omitted", dynamic: "no runtime/load locally" }
finding_counts:
  by_impact: { critical: 1, major: 4, minor: 8 }
  by_lane: { algorithmic: 5, memory: 3, data-access: 5, concurrency: 6 }
  suspected_bugs: 2
regression: { prev_run_id: null, new: 13, persisting: 0, resolved: 0 }
---

# Performance Audit (consolidated + validated) — S5 Async delivery & per-request overhead

**Scope:** internal/{notify,worker,secure}/**, delivery/channel/job/security-event stores + handlers
**Stack:** Go 1.26.2 · doyensec/safeurl webhook client · pgx via database/sql. **Tier:** REDUCED (4 lanes). **Verification:** static-only. **Regression:** 13 new.

**Scope-brief corrections (recorded — two lanes independently):** the brief said "rate-limit check runs on
**every** API request"; the code shows the IP/auth and SCIM limiters are wired **only to auth/SCIM
endpoints**, and they are **in-memory** (no DB round-trip per request). So limiter-mutex contention is
MINOR (auth/SCIM QPS), not a global hot-path critical. **Honest non-findings (verified):** no DB tx is
held across an outbound webhook; fan-out uses `sync.WaitGroup`, not `errgroup`; the security-event channel
**drops** on a full 50-slot semaphore (bounded backpressure, no unbounded buffer); per-org delivery
semaphores are reaped on a ticker; the delivery-list handler is a single keyset query (no N+1).

## Critical Findings

### P1. Alert fan-out is N+1 per matched CVE: invariant channel-list re-query + snapshot re-fetch/re-marshal + per-channel transaction
**Lanes:** data-access (critical), algorithmic (×2), memory (agreement ×4)  **Location:** `internal/notify/dispatcher.go:46-73`, driven per matched CVE at `internal/alert/evaluator.go:434-445` — **this is the canonical owner of S2's cross-slice reference**
**Fingerprint:** `data-access:notify/dispatcher.go:Fanout:per-cve-nplus1`  **Status:** new
**Problem:** `Fanout` is single-CVE; the evaluator calls it once per matched CVE. Each call (validated by reading `dispatcher.go:47-72`): re-runs `ListActiveChannelsForFanout(ruleID, orgID)` — **invariant per (rule, org)** — then `GetCVESnapshot(cveID)` + `json.Marshal`, then loops channels doing `UpsertDelivery`, **each its own `withBypassRawTx`** (Begin + a separate `SET LOCAL app.bypass_rls` round-trip + INSERT + Commit). For a rule matching M CVEs over C channels: ≈ M × (channel-list JOIN + snapshot + marshal + C × 4 round-trips). An activation scan can match up to the 5,000-candidate cap.
**Impact:** reachability = every firing rule (realtime + batch + activation); frequency = matches × channels; per-occurrence = ~`M×(9+4C)` round-trips. **Confidence:** Strong-static  **Effort:** Contained — hoist the channel-list + (where the CVE is constant) snapshot/marshal out of the per-CVE loop; batch the per-channel upserts into one multi-row `INSERT … ON CONFLICT` in a single tx (preserving per-channel error isolation via per-row outcomes).
**Blast radius:** `Fanout`'s "fire-and-forget, per-channel errors logged" contract must hold; the multi-row upsert must still report per-channel failures. Idempotent on `UpsertDelivery` (debounce key).
**Verification plan:** round-trip argument (M×(1+C-tx) → 1 channel-list + batched upserts per rule); correctness guard = a fan-out test asserting one delivery row per (channel, debounce-window) with per-channel error isolation preserved.

## Major Findings

### P2. Single-row reads pay full `withBypassTx` overhead (~4 round-trips for ~1 statement) on the delivery/email hot path
**Lanes:** data-access  **Location:** `internal/store/store.go:48-67`; call sites `internal/notify/worker.go:288,305,310`, `internal/store/alert_rule.go:283`
**Fingerprint:** `data-access:store.go:withBypassTx:single-row-overhead`  **Status:** new
**Problem:** Every helper wraps a trivial single-row SELECT in `BeginTx` + a **separate** `SET LOCAL app.bypass_rls='on'` round-trip + the query + `Commit` — ~4 round-trips for one statement. **Validated:** confirmed at `store.go:54-67`. `GetCVESnapshot` already demonstrates the cheap direct-`s.q` path for bypass-safe reads.
**Impact:** ~3 wasted round-trips per single-row bypass read × delivery/email volume. **Confidence:** Strong-static  **Effort:** Contained — a direct (non-tx) read path for single-statement bypass reads, or fold `SET LOCAL` into a session default for the bypass role.
**Verification plan:** round-trip argument; guard = RLS-bypass semantics preserved (still cannot read org data without bypass).

### P3. Worker pool admits only one job per poll tick — concurrency ramps serially, throughput-capped per queue
**Lanes:** concurrency  **Location:** `internal/worker/pool.go:158-179`
**Fingerprint:** `concurrency:worker/pool.go:one-job-per-tick`  **Status:** new
**Problem:** `runQueue` admits at most one job per `pollInterval` tick (validated: the `select` claims a single sem slot + `processOne` per tick), so a queue with concurrency N takes N×`pollInterval` to saturate and is throughput-capped at `1/pollInterval` jobs/s/queue even with idle slots. The delivery worker's batch-claim is the pattern the generic pool is missing. (Compounds S3-P5's concurrency-1 `feed_ingest`.)
**Impact:** queue throughput ceiling + slow ramp; matters most for high-volume short jobs (alert/retention/notification queues). **Confidence:** Strong-static  **Effort:** Contained — claim up to the free-slot count per tick (batch claim), or event-driven wakeups.
**Verification plan:** throughput argument (1/tick → free-slots/tick); guard = `FOR UPDATE SKIP LOCKED` still prevents double-claim under parallel admission.

### P4. Webhook client leaves `MaxIdleConnsPerHost` at the default of 2 despite `MaxConnsPerHost=50`
**Lanes:** concurrency  **Location:** `internal/notify/client.go:23-25`
**Fingerprint:** `concurrency:notify/client.go:maxidleconns-default`  **Status:** new
**Problem:** A 50-wide fan-out burst to a shared webhook host keeps only 2 idle connections, forcing ~48 TCP+TLS handshakes per burst. **Validated:** confirmed — `MaxConnsPerHost` set, `MaxIdleConnsPerHost` unset (defaults to 2). **Impact:** per-burst connection churn to busy webhook hosts. **Confidence:** Strong-static  **Effort:** Localized — set `MaxIdleConnsPerHost` to match the concurrency. Compounded by P9 (4 KiB body drain prevents reuse).
**Verification plan:** connection-reuse argument; guard = SSRF protections (safeurl) unchanged.

### P5. Security-event writer uses one goroutine + one transaction per event and sheds events under burst
**Lanes:** data-access, algorithmic, concurrency  **Location:** `internal/secure/writer.go:71-136`, `internal/store/security_events.go:30-63`
**Fingerprint:** `data-access:secure/writer.go:per-event-tx-no-batch`  **Status:** new
**Problem:** A 50-way per-event goroutine pool, each event a full single-row-INSERT transaction; once slots fill the writer **drops** events. Under a multi-IP brute-force burst (which the limiter doesn't coalesce) it pays the `SET LOCAL`/tx tax per event and **sheds audit signal early** — the worst time to lose security telemetry. **Validated:** confirmed.
**Impact:** tx-per-event + early loss of security events under attack load. **Confidence:** Strong-static  **Effort:** Contained — a batched channel-drainer (collect N events, one multi-row INSERT) raises throughput and the effective drop threshold. **Blast radius:** preserve the bounded-memory drop semantics (don't reintroduce an unbounded buffer).
**Verification plan:** throughput argument (per-event tx → batched insert); guard = drop-on-overflow still bounded; events not lost below the new threshold.

## Minor Findings
- **P6** `memory:notify/webhook.go:hmac-string-concat` — `internal/notify/webhook.go:60,67`: HMAC rebuilds `ts+"."+payload` (~3 payload copies, ×2 during key rotation); `hmac.Hash` is an `io.Writer` — write segments, zero copies. Localized.
- **P7** `concurrency:notify/webhook.go:body-drain-4kib` — `webhook.go:78`: response body drained only to 4 KiB, so >4 KiB responses make `net/http` close (not pool) the conn — compounds P4. Localized (drain+discard fully, with a sane cap).
- **P8** `algorithmic:api/ratelimit.go:global-mutex` — `api/ratelimit.go:45`, `scim_ratelimit.go:48`, `secure/ratelimit.go:50`: one global mutex per limiter on the read-mostly path; bounded to auth/SCIM QPS (scope-corrected → MINOR). Shard / `sync.Map`. Localized.
- **P9** `memory:api/deliveries.go:replaybuckets-no-evict` — `api/deliveries.go:27,33-52`: replay-protection `sync.Map` never evicts (one entry/org forever) — the lone unbounded-retention site; the other limiters have TTL sweeps. Localized (add a TTL sweep for parity).
- **P10** `data-access:jobs.sql:idx-order-mismatch` — `migrations/000001:38-39` vs `jobs.sql:11-19`: `job_queue_runnable_idx (queue,status,run_after,priority DESC)` can't satisfy the claim's `ORDER BY priority DESC, created_at`, forcing a sort each poll. Localized (align the index).
- **P11** `data-access:notification_delivery.go:two-statement-claim` — `notification_delivery.go:53-71`: claim does `SELECT … FOR UPDATE SKIP LOCKED` + a separate `MarkDeliveriesProcessing`; the job-queue path does it in one `UPDATE … RETURNING`. Localized.
- **P12** `concurrency:notify/worker.go:per-row-lookup-no-memo` — `worker.go:284-312`: email delivery does 1–2 redundant rule/report/org lookups per delivery row with no memoization within a 50-row claim batch. Localized (memoize per batch). Related to P2.
- **P13** `concurrency:notify/worker.go:claim-batch-vs-pool` — `worker.go:152-177` vs `config.go:20`: `ClaimBatchSize=50` × org spread can exceed `DB_MAX_CONNS=25`; effective parallelism is pool-capped (transient, no deadlock — HTTP holds no conn). DEFEND/sizing note.

## Measurability
Delivery latency + webhook connection-reuse + security-event drop rate are all observable with counters
(deliveries/s, webhook dial count, dropped-events counter). Recommend a dropped-security-event metric
before P5 so the shed rate is visible.

## Suspected Bugs (for follow-up — NOT addressed here)
> Kickoff: `docs/perf-audits/2026-06-05-s5-delivery-bug-hunt-kickoff.md`.
- **SB1.** `evictStaleSemaphores` len-check race can transiently double an org's delivery concurrency cap — `internal/notify/worker.go:403-413`.
- **SB2.** Uncapped exponential `backoffSeconds` — `internal/notify/worker.go:384` — retry backoff can grow without bound.

---
**Disposition:** all 13 findings default to **FIX** (P1 is the headline — the canonical fix for S2's
cross-slice fan-out reference). No severity/effort deferral. 2 suspected bugs handed off.
