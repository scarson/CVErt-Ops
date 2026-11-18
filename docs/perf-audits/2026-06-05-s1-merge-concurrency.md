# S1 Merge & corpus write path — concurrency & parallelization lane

ABOUTME: Performance audit of the merge pipeline's concurrency/parallelization, both exploit and defend.
ABOUTME: Covers serial ingest loops, advisory-lock critical-section width, and inline alert eval.

**Slice:** S1 "Merge & corpus write path" (FULL, HOT)
**Lane:** concurrency & parallelization (both directions)
**Sources read:** `internal/merge/pipeline.go`, `internal/merge/advisory.go`, `internal/merge/store.go`,
`internal/store/cve.go`, `internal/store/store.go`, `internal/ingest/handler.go`, `internal/ingest/epss.go`,
`internal/feed/epss/adapter.go`, `internal/worker/pool.go`, `cmd/cvert-ops/main.go` (pool/registration/sizing).
No runtime profiling available — all confidence is `Strong-static` or `Heuristic`, never `Measured`.

## Call-path facts (established, not assumed)

- `feed_ingest` and `epss_ingest` are registered with `Pool.Register(...)` (`cmd/cvert-ops/main.go:186-194`,
  `437-445`), which is `RegisterWithConcurrency(..., 1)` — **per-queue concurrency 1**. One feed job and one
  EPSS job run at a time, ever.
- Within a single `feed_ingest` job, `handler.go:163-211` merges every patch **serially** in a `for` loop,
  one `merge.Ingest` (= one transaction) per patch.
- `merge.Ingest` (`pipeline.go:38-294`) acquires `pg_advisory_xact_lock(CVEAdvisoryKey(cveID))` at step 1
  (`pipeline.go:60`) and holds it for the **entire transaction**: re-read all sources, resolve, hash, upsert
  `cves`, tombstone, delete+re-insert references/packages/CPEs (per-row inserts in loops), vendor enrichment,
  EPSS staging drain, FTS upsert, then `tx.Commit()`. The lock is `xact`-scoped, so it is held until commit.
- EPSS `Apply` (`epss/adapter.go:202-232`) applies ~250,000 rows **serially**, one `applyRow` transaction
  (`adapter.go:250-287`) + one advisory lock per row.
- Realtime alert evaluation (`handler.go:193-210`) runs **inline and serially** between merges in the same loop.

---

## Findings

### MAJOR — Advisory lock held across the entire re-read + recompute + child-table rewrite + commit, widening the critical section far beyond the TOCTOU window it exists to protect
**Location:** `internal/merge/pipeline.go:60` (lock acquire) through `:293` (commit); contended against `internal/feed/epss/adapter.go:260`
**Problem:** The per-CVE advisory lock is taken as the first statement of the transaction and released only at
commit. Between those points the pipeline does a full re-read of all `cve_sources`, in-memory resolve+hash, an
upsert of `cves`, a `DELETE` + N per-row `INSERT`s into three child tables (`cve_references`,
`cve_affected_packages`, `cve_affected_cpes`), optional vendor-enrichment upsert, an EPSS-staging select +
update + delete, and an FTS upsert — easily 10–30+ DB round-trips for a rich CVE (NVD CVEs with many CPEs/refs
inflate the per-row insert count). Every one of those round-trips happens *while the lock is held*. The lock's
stated purpose (§5.3, and the comments at `advisory.go:1-7`, `epss/adapter.go:257-261`) is narrowly to close a
TOCTOU race between the merge's source-read/resolve and the EPSS two-statement write — i.e. it must cover the
read of `cve_sources` + the `cves`/`epss_staging` mutation. It does **not** need to also cover the child-table
DELETE/INSERT storm or the FTS upsert, which touch different tables and are not part of the EPSS race.
**Impact:** The lock is the single serialization point shared by merge ↔ EPSS for a given CVE. Per-occurrence
cost = full transaction wall-time (dominated by round-trip count for child tables), not the few-µs hash/resolve
window. During EPSS day (250k serial `applyRow`s) overlapping a concurrent NVD/GHSA re-ingest of the same hot
CVE, the EPSS row blocks on the lock for the *whole* merge transaction including the per-row child inserts.
Because both feed_ingest and epss_ingest are concurrency-1 queues, same-queue contention is nil, but
**cross-queue** merge↔EPSS contention on a hot CVE is real and the held duration is unnecessarily long.
Reachability: every merge + every EPSS row. Frequency: high. Per-occurrence: O(refs+pkgs+cpes) round-trips
under lock instead of O(1).
**Confidence:** Strong-static (lock span is literally acquire-at-:60, release-at-commit-:293; child inserts are
in-loop between them).
**Effort:** Contained — the correctness constraint is that the lock must wrap *source-read → resolve →
cves/epss mutation* atomically. The child-table rewrite (refs/pkgs/CPEs) and FTS upsert are derived outputs that
no other writer races on under the same key; they could move after the EPSS-staging drain but still inside the
same transaction, OR the lock could be scoped to only the EPSS-sensitive region. The simplest safe win:
**reorder** so the EPSS-staging select/update/delete (step 9) and the `cves` upsert (step 6) sit as early as
possible after the source read, and keep the child-table rewrite last — the lock still wraps everything (one
xact lock can't be released mid-transaction without `pg_advisory_unlock`, which is session-scoped not xact-
scoped), so the *real* fix is to shrink what runs between resolve and commit, e.g. batch the child-table inserts
(see next finding) so the lock-held round-trip count drops. Cross-cutting if you split the EPSS-critical region
into its own short transaction — that changes the atomicity model and needs §5.3 sign-off.
**Verification plan:** Count DB round-trips executed between `:60` and `:293` for a CVE with R refs, P pkgs,
C cpes — currently ≈ 8 + R + P + C individual `Exec`s; batching child inserts drops the under-lock count to a
small constant. Correctness guard: `pipeline_integration_test.go` already exercises concurrent same-CVE merge
and the EPSS TOCTOU path (`apply_integration_test.go`); pin behavior with a test that interleaves an EPSS
`applyRow` and a `merge.Ingest` for the same CVE and asserts the final `epss_score` + `material_hash` are
identical regardless of interleaving. Do NOT reduce the region below {source-read, cves upsert, epss-staging
drain} — that set must stay atomic under the lock.

### MAJOR — Child-table rewrite issues one round-trip per reference / package / CPE inside the locked transaction; should be a single multi-row insert (or COPY)
**Location:** `internal/merge/pipeline.go:193-206` (references), `:212-226` (packages), `:232-240` (CPEs)
**Problem:** After `DELETE FROM <child>`, each resolved row is inserted with its own
`q.InsertCVEReference` / `q.InsertAffectedPackage` / `q.InsertAffectedCPE` call — N separate network
round-trips per child table. An NVD CVE commonly has dozens of CPEs and references; GHSA/OSV CVEs carry many
affected-package ranges. Every one of these round-trips executes **while the advisory lock is held** (see prior
finding), so this is both an allocation/round-trip cost and a lock-hold-time amplifier.
**Impact:** Per merge of a rich CVE: tens of serial INSERT round-trips, each ~one network RTT, all under the
per-CVE lock and inside the serial per-patch loop. With feed_ingest at concurrency 1, total feed throughput is
gated by exactly this: `sum over patches of (RTT × (refs+pkgs+cpes)))`. Reachable on every merge that has child
data; frequency = every NVD/GHSA/OSV patch. This is the dominant per-merge latency term and it directly inflates
the critical section.
**Confidence:** Strong-static (loops with per-iteration `q.Insert*` are visible at the cited lines).
**Effort:** Contained — replace the per-row loops with a single parameterized multi-row `INSERT ... VALUES (...),
(...), ... ON CONFLICT DO NOTHING` per child table (sqlc supports `:batch` / `pgx.Batch`, or a hand-written
multi-row insert via the existing `generated` layer; `cve_affected_packages` has no ON CONFLICT today and would
just be a plain multi-row insert). For the largest feeds, `pgx CopyFrom` into a temp/staging shape is the upper
bound but is heavier; the multi-row VALUES insert captures most of the win with far less code. Keep the
DELETE+reinsert semantics (full replace) — only the insert shape changes.
**Verification plan:** Round-trip count for a CVE with R+P+C child rows drops from R+P+C inserts to 3 inserts
(one per table). No fabricated timings. Correctness guard: existing `pipeline_integration_test.go` cases that
assert references/packages/CPEs round-trip correctly (and the ON CONFLICT dedup on `url_canonical` /
`cpe_normalized`) must stay green; add a case with duplicate URLs/CPEs in the resolved set to confirm the
multi-row `ON CONFLICT DO NOTHING` still dedups within a single statement.

### MAJOR — feed_ingest merges every patch serially with no intra-feed parallelism, even though distinct CVE IDs are provably independent
**Location:** `internal/ingest/handler.go:163-211` (serial per-patch loop), enabled by `cmd/cvert-ops/main.go:186-188` (`Register` ⇒ concurrency 1)
**Problem:** A single feed page yields `result.Patches` for many *distinct* CVE IDs. They are merged one at a
time, each in its own transaction. The advisory-lock design guarantees that only **same-CVE** writes must
serialize; **cross-CVE** merges are independent (different lock keys, disjoint `cves`/child rows). Yet the loop
processes them strictly sequentially, and the queue itself is concurrency-1, so there is no parallelism at any
level for a feed that delivers thousands of patches.
**Impact:** Total feed catch-up time = Σ per-patch transaction time, fully serial. For a large NVD backfill or a
big GHSA page this is the throughput ceiling. The work is embarrassingly parallel across distinct CVE IDs and the
DB pool is sized for it (`DB_MAX_CONNS` default 25; merge currently uses 1 conn at a time). Reachability: every
multi-patch page. Frequency: every feed run. Per-occurrence: N× serialization where N = patches/page.
**Confidence:** Strong-static for the serial structure; Heuristic for the magnitude of the win (depends on RTT
vs CPU split, which can't be measured here).
**Effort:** Contained-to-Cross-cutting. The correctness guard is mandatory and non-trivial: **dedupe by CVE ID
within the bounded fan-out** so two patches for the same CVE in one page never run concurrently (the advisory
lock would still serialize them at the DB, but you'd waste a connection blocking on the lock and risk pool
starvation — see the DEFEND finding). Concretely: group `result.Patches` by `patch.CVEID`, then fan out across
groups with an `errgroup.Group` + `g.SetLimit(k)` where `k` is comfortably below `DB_MAX_CONNS` minus headroom
for alert-eval/other queues. Within a group, process sequentially. The late-binding PK migration
(`pipeline.go:67-98`, OSV/GHSA alias → CVE promotion) takes a *second* advisory lock and is the one place where
two *different* keys interact; bound `k` and keep the deadlock note in mind (Postgres detector handles it, but
contention rises). Also: realtime alert eval is currently inline in this loop (next finding) — parallelizing the
merge loop without addressing eval placement changes ordering of eval triggers.
**Verification plan:** Argue independence: distinct CVE IDs ⇒ distinct advisory keys ⇒ disjoint row sets ⇒ no
shared mutable state. The only cross-CVE coupling is the alias-promotion path, which is gated by
`patch.SourceID != "" && patch.CVEID != patch.SourceID` and self-serializes via the second lock. Correctness
guard: add an integration test that ingests a page containing (a) two patches for the same CVE ID and (b) an
alias-promotion patch alongside an independent CVE, run under the parallel path, and assert the resolved corpus
is byte-identical to the serial path. Do NOT parallelize until same-CVE grouping is in place. Confidence on the
*existence* of the opportunity is Strong-static; on the *realized speedup* it is Heuristic (no profile).

### MINOR — Inline, serial realtime alert evaluation inside the merge loop blocks the next patch's merge
**Location:** `internal/ingest/handler.go:193-210`
**Problem:** After each merge that changes `material_hash`, the handler calls
`eval.EvaluateRealtime(ctx, patch.CVEID)` **synchronously inside the per-patch loop**, plus two extra
`GetCVEMaterialHash` round-trips (`:169`, `:194`) per patch for change detection. The next patch's merge cannot
start until evaluation returns. Alert evaluation can itself be non-trivial (rule scan), so a feed with many
hash-changing CVEs interleaves merge and eval strictly sequentially.
**Impact:** Per hash-changing patch: 2 extra SELECT round-trips + the full `EvaluateRealtime` cost, all on the
critical feed-throughput path, all serial. Reachability: only when `eval != nil && hashReader != nil` (the
production `HandlerWith*AndAlerts` path — i.e. always in prod). Frequency: every patch whose hash changes.
Note the merge transaction has already committed before eval runs (eval is *outside* the advisory lock), so this
is feed-throughput cost, not lock-hold cost.
**Confidence:** Strong-static (inline call in the loop body).
**Effort:** Contained — decouple eval from the merge loop: enqueue affected CVE IDs (dedup) and run evaluation
after the page/feed completes, or hand them to a separate bounded worker, so merges aren't blocked. The two
hash-read round-trips could collapse into one if `UpsertCVE` returned the prior/new hash (the `cves` upsert
already computes it) — `GetCVEMaterialHash` is a separate `s.db.QueryRowContext` (`store/cve.go:32-44`) issued
twice per patch. Keep at-least-once eval semantics; the realtime path already tolerates redundant eval (alert
inserts are `ON CONFLICT DO NOTHING`).
**Verification plan:** Round-trips per hash-changing patch drop from {pre-read, merge txn, post-read, eval} to
{merge txn returning hash, deferred eval}. Correctness guard: existing realtime-eval tests must still fire an
alert exactly when `material_hash` transitions; add a test asserting that deferring eval to end-of-page still
produces the same `alert_events` rows (dedup makes re-eval safe).

### MINOR — EPSS applies ~250k rows fully serially, one transaction + one advisory-lock round-trip per row
**Location:** `internal/feed/epss/adapter.go:202-232` (serial row loop) → `:250-287` (`applyRow`: BeginTx + advisory lock + 2 statements + Commit per row)
**Problem:** The daily EPSS file (~250,000 rows) is applied one row at a time, each in its own transaction that
takes the per-CVE advisory lock, runs two statements, and commits. That's ~250k × (BeginTx + advisory-lock
acquire + 2 Exec + Commit) round-trips, strictly serial, on a concurrency-1 queue.
**Impact:** Reachability: once daily (the cursor short-circuit at `adapter.go:121-129` skips same-day reruns).
Frequency: low (daily), but per-occurrence is enormous — ~1M+ DB round-trips serialized through one connection.
This is bounded and off the API hot path, so it's MINOR by the calibration rule (frequency dominates), but it is
the largest single serial DB workload in the slice and a clear pipelining candidate.
**Confidence:** Strong-static (per-row transaction loop is explicit).
**Effort:** Contained — two independent levers, both respecting the §5.3 lock: (1) **parallelize across distinct
CVE IDs** with a bounded `errgroup` (EPSS rows are unique per CVE within a file, so every row is an independent
lock key — no same-key contention *within* the file; the lock only matters against concurrent *merge* writers);
(2) **batch** the two-statement pattern across many CVEs per transaction to amortize BeginTx/Commit. The lock is
per-CVE `xact`-scoped, so a multi-CVE transaction would hold multiple advisory locks simultaneously — acquire
them in sorted key order to avoid deadlock against merge, or keep transactions per-CVE but fan out across a
bounded pool. Bound concurrency below `DB_MAX_CONNS`. Note: EPSS day is exactly when cross-queue contention with
merge is most likely, so the bound must leave headroom (ties into the DEFEND finding below).
**Verification plan:** Round-trips drop from ~250k×5 serial to (250k×5)/k with k-way fan-out, or to
~250k×(2/B)+overhead with batch size B. Correctness guard: `apply_integration_test.go` must still produce
identical `cves.epss_score` and `epss_staging` rows; add a test that runs a concurrent `merge.Ingest` for a CVE
present in the EPSS batch and asserts no lost update in either direction (the TOCTOU invariant §5.3 protects).
Do NOT batch across CVEs without sorted-key lock acquisition.

### MINOR (DEFEND) — Bounded fan-out (if added) plus advisory-lock-while-holding-an-open-transaction can starve the pgx pool; same-key blocking wastes a held connection
**Location:** Design constraint spanning `internal/merge/pipeline.go:60`, `internal/feed/epss/adapter.go:260`, pool sizing `cmd/cvert-ops/main.go:750` (`DB_MAX_CONNS` default 25)
**Problem:** This is a forward-looking guard for the EXPLOIT findings above, but it also names a current latent
risk. Every `pg_advisory_xact_lock` call blocks **while holding an open transaction and its pooled connection**.
Today, with feed_ingest and epss_ingest both at concurrency 1, at most a handful of connections are ever blocked
on locks, so pool exhaustion isn't reachable. But the moment intra-feed or intra-EPSS parallelism is introduced
(EXPLOIT findings), each goroutine that blocks on `pg_advisory_xact_lock` for a contended CVE pins one pool
connection *for the entire wait*. If the fan-out width approaches `DB_MAX_CONNS`, a burst of same-CVE contention
(e.g., EPSS day overlapping an NVD re-ingest of a hot CVE) can occupy most of the pool with connections that are
all just *waiting on a lock*, starving merge, alert eval, and API traffic sharing the same pool.
**Impact:** Not reachable in the current serial design (Strong-static: concurrency-1 queues). Becomes reachable
and potentially severe the moment any EXPLOIT fan-out is implemented — hence recorded as the correctness/safety
guard those findings must attach. Per-occurrence cost when reachable: connection held for the full lock-wait,
multiplied by fan-out width.
**Confidence:** Heuristic (conditional on the EXPLOIT changes being made).
**Effort:** Localized constraint — any fan-out MUST (a) dedupe by CVE ID so same-key writes never run on two
connections at once, and (b) cap concurrency strictly below `DB_MAX_CONNS` minus headroom reserved for API +
other worker queues sharing the pool. Optionally use `pg_try_advisory_xact_lock` + requeue instead of a blocking
acquire so a connection is never parked waiting.
**Verification plan:** With fan-out width k and `DB_MAX_CONNS` = M, assert k + reserved-API-headroom < M.
Correctness guard: a stress test that fans out merges/EPSS rows including deliberate same-CVE collisions and
asserts the pool never reaches saturation (acquired conns < M) and no goroutine blocks indefinitely.

---

## Summary of opportunity

The merge write path is **serial at three nested levels** that the advisory-lock design does not actually
require to be serial:

1. **Queue level** — `feed_ingest`/`epss_ingest` at concurrency 1 (a deliberate but possibly conservative
   choice given the per-CVE lock already provides correctness).
2. **Loop level** — patches/rows processed one at a time despite distinct CVE IDs being independent.
3. **Within the lock** — the critical section spans the full child-table rewrite + FTS + commit, not just the
   §5.3-mandated source-read→mutation window, and the child rewrite is per-row round-trips.

The two highest-leverage, lowest-risk changes are **batching the child-table inserts** (MAJOR, Contained,
shrinks the lock-held round-trip count with no concurrency-model change) and **bounded cross-CVE fan-out with
same-CVE dedup** (MAJOR, Contained-to-Cross-cutting, needs the pool-headroom guard). Every parallelization
finding carries the same correctness invariant: **same-CVE writes must serialize (respect the advisory key);
cross-CVE writes are independent**, and any fan-out must dedupe by CVE ID and stay under `DB_MAX_CONNS`.

## Suspected Bugs (for follow-up)

None observed in this lane. (The PK-migration double-lock at `pipeline.go:85-92` notes a theoretical deadlock
between two concurrent cross-referencing PK migrations; the code comment acknowledges it and relies on
Postgres's deadlock detector. Not a performance issue and behavior is documented, so not chased — recorded here
only because any fan-out over the merge loop raises the probability of that path running concurrently.)
