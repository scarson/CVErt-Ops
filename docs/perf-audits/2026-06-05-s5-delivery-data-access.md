# S5 — Async Delivery & Per-Request Overhead — Data Access & I/O Lane

ABOUTME: Performance audit (data-access lane) of notification fan-out, delivery worker, job queue, rate limiters, and the security-event writer.
ABOUTME: All findings are static; no runtime profiling available in this container.

Scope examined: `internal/notify/{dispatcher,worker,digest}.go`, `internal/worker/pool.go`,
`internal/secure/{writer,events,ratelimit}.go`, `internal/store/{notification_delivery,alert_rule_channel,report_channel,jobs,security_events,cve}.go` + their `.sql` files, the relevant `migrations/` DDL/indexes, and the API-side rate limiters / lockout / delivery list handlers.

A recurring structural fact underpins several findings: **every `withBypassTx` / `withBypassRawTx` / `withOrgTx` call is a full transaction** — `BeginTx` + a *separate* `ExecContext("SET LOCAL app.bypass_rls = 'on'")` + the query + `Commit` (`internal/store/store.go:48-93`). Under `QueryExecModeSimpleProtocol` (PgBouncer compat) each of those is its own network round-trip, so **one logical single-row operation costs ~4 round-trips**. This multiplies the cost of every N+1 below.

---

### [CRITICAL] Fan-out issues N+1 transactions per matched CVE: per-channel `UpsertDelivery` + per-CVE channel re-query + per-CVE snapshot refetch

**Location:** `internal/notify/dispatcher.go:46-75` (`Fanout`), called per matched CVE at `internal/alert/evaluator.go:434-445`; `internal/store/notification_delivery.go:39-47` (`UpsertDelivery` → `withBypassRawTx`); `internal/store/alert_rule_channel.go:72-86` (`ListActiveChannelsForFanout` → `withBypassTx`).

**Problem:** `evaluateRule` loops over every matched CVE and calls `Fanout(orgID, ruleID, cveID)` once per CVE. Each `Fanout` call:
1. re-runs `ListActiveChannelsForFanout(ruleID, orgID)` — **identical arguments for every CVE in the same rule's batch**, so the channel list is fetched M times for M matches instead of once;
2. runs `GetCVESnapshot(cveID)` — a fresh single-row read even though the candidate row for that CVE was already materialized in `queryCandidates` (`evaluator.go:470-508`) just moments earlier (the candidate query deliberately selects only 3 columns, so the snapshot columns genuinely aren't carried — but they could be);
3. for each of C channels, calls `UpsertDelivery`, and **each upsert is its own `withBypassRawTx`** (Begin + SET LOCAL + INSERT + Commit).

Plus the preceding `InsertAlertEvent` (`evaluator.go:436`) is itself a `withBypassTx`.

So per matched CVE the DB round-trip count is roughly:
`InsertAlertEvent (~4) + ListActiveChannelsForFanout (~4) + GetCVESnapshot (1) + C × UpsertDelivery (~4 each)`.

For a rule with C channels matching M CVEs: **≈ M × (9 + 4C) round-trips**. A batch run where a single new high-severity CVE matches many rules, or a rule that suddenly matches a backlog of M CVEs (activation / re-scan), turns into thousands of tiny transactions. This is the single largest data-access cost on the delivery hot path and was flagged from S2.

**Impact:** Reachable on every realtime upsert and every batch/EPSS evaluation tick (the core product loop). Frequency scales with match count × channel count. Per-occurrence: O(C) separate transactions per CVE, each ~4 round-trips, plus a redundant channel-list query and snapshot read per CVE. Aggregate: dominant DB chatter of the notification subsystem.

**Confidence:** Strong-static — the loop structure, the per-call transaction helpers, and the constant `(ruleID, orgID)` arguments are all visible in source.

**Effort:** Contained — within `notify`/`alert`/`store`. Three independent wins, increasing order of effort:
- Hoist `ListActiveChannelsForFanout` out of the per-CVE loop: change the evaluator to gather matched `(cveID, materialHash)` for the rule, fetch the channel list **once**, then fan out. (Largest, cheapest win.)
- Batch the per-channel `UpsertDelivery` into a single multi-row `INSERT ... ON CONFLICT` (or one transaction looping the channels) instead of C transactions.
- Optionally widen `queryCandidates` to carry snapshot fields and drop the per-CVE `GetCVESnapshot` entirely.

**Verification plan:** Argue round-trip count before/after for a fixed (M matches, C channels) rule — N+1 → 1 channel query, C transactions → 1. Correctness guard: a test that pins (a) one `notification_deliveries` row per `(rule_id, channel_id)` with the payload array containing all M coalesced snapshots, and (b) identical debounce/`send_after` semantics via the existing `uq_deliveries_pending_alert` ON CONFLICT path (`dispatcher_test.go`, `worker_test.go` coalescing cases).

---

### [MAJOR] Single-row reads pay full-transaction overhead via `withBypassTx` across the delivery worker hot path

**Location:** `internal/store/alert_rule.go:283` (`InsertAlertEvent`), `internal/store/scheduled_report.go:157,175` (`GetAlertRuleName`, `GetScheduledReportName`), `internal/store/org.go:145` (`GetOrgByID`), `internal/store/security_events.go:31` (`InsertSecurityEvent`); helper at `internal/store/store.go:48-67`.

**Problem:** `withBypassTx` wraps even trivial single-statement reads/writes in `BeginTx` + a separate `SET LOCAL app.bypass_rls = 'on'` round-trip + `Commit`. For a single-row SELECT that touches a non-org-scoped table, the `SET LOCAL` and the surrounding transaction add ~3 extra round-trips that buy nothing (no multi-statement atomicity is needed, and `GetCVESnapshot` already demonstrates the cheap path — `s.q.GetCVESnapshot` directly, `cve.go:234`, no tx). The email delivery path hits several of these *per delivery*: `deliverEmail` calls `GetAlertRuleName` (alert kind) or `GetScheduledReportName` + `GetOrgByID` (digest kind) on every send (`worker.go:288,305,310`).

**Impact:** Reachable on every email delivery and every alert-event insert (the latter is inside the CRITICAL fan-out loop, compounding it). Per-occurrence: ~3 avoidable round-trips per call. Frequency: once per delivery for the name/org lookups; M times per rule batch for `InsertAlertEvent`.

**Confidence:** Strong-static — helper body and call sites are explicit.

**Effort:** Contained — add a non-transactional `s.q.<Query>` path for the read-only single-row helpers (mirroring `GetCVESnapshot`), or a `withBypassExec` that issues the statement with a session-level `bypass_rls` GUC rather than per-call `SET LOCAL`. Touches the store helpers + a handful of call sites; behavior-preserving since these reads need no transaction.

**Verification plan:** Show that the read-only helpers require no multi-statement atomicity, so dropping the transaction wrapper removes Begin/SET LOCAL/Commit (≈4 → 1 round-trip). Correctness guard: RLS-bypass tests must still confirm the queries return rows for cross-org/global tables (existing store tests for these methods).

---

### [MAJOR] Security-event writer inserts one row per transaction with no batching; one goroutine + one full transaction per event

**Location:** `internal/secure/writer.go:71-136` (`Write`), `internal/store/security_events.go:30-63` (`InsertSecurityEvent` → `withBypassTx`).

**Problem:** Each security event spawns a goroutine (bounded to 50) that performs one `InsertSecurityEvent` — and that insert is a full `withBypassTx` (Begin + SET LOCAL + INSERT + Commit ≈ 4 round-trips). There is no buffering/batching: under a burst (credential-stuffing / scan across many source IPs, where the per-`(type,ip)` rate limiter at `writer.go:72-73` does *not* coalesce because the IPs differ), the writer fans out to 50 concurrent single-row transactions, each paying the SET LOCAL tax, and silently **drops** events once all 50 slots are busy (`writer.go:86-90`, `metrics.SecurityEventsDropped`). Dropping is the intended backpressure, but it's reached far sooner than necessary because each slot holds a 4-round-trip transaction instead of contributing to a batched insert.

**Impact:** Reachable on every auth/SCIM security event; the burst case is exactly the brute-force scenario this pipeline exists to record. Per-occurrence: ~4 round-trips + a goroutine per event vs. amortized ~1 insert per N events with a batching buffer. Higher drop rate (lost audit signal) under load is the user-visible symptom.

**Confidence:** Strong-static for the per-event transaction shape; Heuristic on burst magnitude (no runtime numbers).

**Effort:** Contained — introduce a buffered channel + a single drain goroutine that flushes accumulated events with a multi-row `INSERT` (or `COPY`) on a short timer / size threshold, replacing the 50-way per-event goroutine pool. A store method `InsertSecurityEvents(batch)` in one transaction. Localized to `secure/writer.go` + one new store method.

**Verification plan:** Argue transactions/event drops from O(events) to O(events/batch). Correctness guard: tests asserting all non-rate-limited events are persisted (ordering not required), syslog forwarding still fires per event, and graceful-drain on `Stop()` flushes the buffer (extend `writer_test.go`).

---

### [MINOR] `job_queue` claim index column order doesn't match the claim query's sort, forcing a partial sort

**Location:** `internal/store/queries/jobs.sql:1-20` (`ClaimJob`); index `migrations/000001_create_job_queue.up.sql:38-39` `job_queue_runnable_idx ON (queue, status, run_after, priority DESC)`.

**Problem:** `ClaimJob` filters `queue = $1 AND status = 'pending' AND run_after <= now()` and orders `priority DESC, created_at`. The index leads with `(queue, status, run_after, ...)`, so `run_after <= now()` is a range predicate sitting *before* the sort keys in the index — Postgres can use the index for the `queue`/`status` equality + `run_after` range but cannot return rows already ordered by `priority DESC, created_at`; it must sort the matching set (or scan more of the index than needed) before `LIMIT 1 FOR UPDATE SKIP LOCKED`. For a queue with a deep pending backlog this is a sort over the runnable set on every poll. Polling is every 2s per queue (`pool.go:30`), so the frequency is modest, and `created_at` isn't even in the index, guaranteeing the tiebreak can't be index-ordered.

**Impact:** Reachable on every job poll (every 2s per queue). Per-occurrence: a sort/extra index scan whose cost grows with pending backlog depth; negligible when the queue is shallow, noticeable during ingest surges. Bounded, hence MINOR.

**Confidence:** Heuristic — exact plan depends on backlog size and Postgres' choice; the column-order mismatch is structural fact, the cost is load-dependent.

**Effort:** Localized — add/replace with a partial index `ON job_queue (queue, priority DESC, created_at) WHERE status = 'pending'` (a new migration) so the runnable scan is index-ordered for the `LIMIT 1`. `run_after <= now()` becomes a cheap filter on the leading rows.

**Verification plan:** `EXPLAIN` the claim subquery before/after on a seeded backlog and confirm the post-change plan drops the Sort node and reads only the leading index entries. Correctness guard: existing job-queue claim/ordering tests (`pool_test.go`) must still claim highest-priority-then-oldest.

---

### [MINOR] `ClaimPendingDeliveries` then `MarkDeliveriesProcessing` is two statements where the claim could mark in one `UPDATE ... RETURNING`

**Location:** `internal/store/notification_delivery.go:53-71`; `internal/store/queries/notification_deliveries.sql:4-15`.

**Problem:** Claiming deliveries does a `SELECT ... FOR UPDATE SKIP LOCKED` (`ClaimPendingDeliveries`) followed by a separate `UPDATE ... WHERE id = ANY($1)` (`MarkDeliveriesProcessing`) inside the same transaction. The job-queue path already shows the better shape — a single `UPDATE ... WHERE id = (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING *` (`jobs.sql:4-20`). The delivery path's two-statement form is an extra round-trip per claim tick (every 5s, `worker.go:77`) and builds an intermediate `ids` slice in Go (`notification_delivery.go:61-64`).

**Impact:** Reachable every 5s on the delivery claim tick. Per-occurrence: one extra round-trip + a slice allocation per batch. Low frequency and small batch sizes make this MINOR, but it's a free simplification that also tightens the claim window.

**Confidence:** Strong-static.

**Effort:** Localized — rewrite as a single CTE `UPDATE ... FROM (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING` mirroring `ClaimJob`. One `.sql` change + regenerate.

**Verification plan:** Confirm the combined statement still transitions exactly the claimed rows to `processing` and returns the same columns. Correctness guard: worker claim tests asserting only-ready (`send_after <= now()`), no double-claim across concurrent workers (`worker_test.go`).

---

## Lane summary (ranked)

1. **CRITICAL** — Fan-out N+1: per-channel `UpsertDelivery` transactions + per-CVE channel-list re-query + per-CVE snapshot refetch — `dispatcher.go:46-75`, `evaluator.go:434-445`, `alert_rule_channel.go:72-86`, `notification_delivery.go:39-47`. ≈ M×(9+4C) round-trips per rule batch.
2. **MAJOR** — Single-row reads pay full `withBypassTx` (Begin + SET LOCAL + Commit) overhead on the delivery/email hot path — `store.go:48-67`, `worker.go:288/305/310`, `alert_rule.go:283`. ~3 avoidable round-trips per call.
3. **MAJOR** — Security-event writer: one full transaction + one goroutine per event, no batching → higher round-trip cost and earlier event drops under burst — `secure/writer.go:71-136`, `security_events.go:30-63`.
4. **MINOR** — `job_queue_runnable_idx` column order mismatches the claim sort, forcing a partial sort per poll — `jobs.sql:11-19`, `migrations/000001:38-39`.
5. **MINOR** — Delivery claim uses two statements (`SELECT FOR UPDATE` + separate `UPDATE`) where one `UPDATE ... RETURNING` suffices — `notification_delivery.go:53-71`.

What I confirmed is NOT a problem: the in-memory IP and SCIM rate limiters (`api/ratelimit.go`, `api/scim_ratelimit.go`) do **no** DB round-trip per request — pure `golang.org/x/time/rate` maps with background eviction. The DB-backed lockout (`api/lockout.go`) only touches the DB on the login path, not the delivery hot path. The delivery list handler (`api/deliveries.go:151-178`) is a single keyset query with in-memory row mapping, no N+1. The `ClaimPendingDeliveries` claim index (`notification_deliveries_claim_idx ON (send_after) WHERE status='pending'`) matches its query well. `GetCVESnapshot` correctly bypasses the transaction wrapper.

## Suspected Bugs (for follow-up)

None observed within this lane's scope.
