# S3 Feed Ingestion — Data-Access & I/O Performance Audit

**Date:** 2026-06-05
**Slice:** S3 "Feed ingestion & adapters" (FULL, HOT)
**Lane:** data-access (N+1 / write-batching / round-trips / pool / index)
**Load profile audited:** NVD ~250k CVEs, EPSS daily ~250k rows; per-CVE writes are the hot path.

Source read: `internal/ingest/{handler,epss}.go`, `internal/merge/{pipeline,store}.go`,
`internal/feed/epss/adapter.go`, `internal/feed/nvd/adapter.go`, `internal/feed/client.go`,
`internal/feed/redhat/adapter.go`, `internal/store/feed.go`, `internal/store/queries/{feed,cves}.sql`,
DDL `migrations/000002_create_cve_core.up.sql`, `000003_create_feed_state.up.sql`, pool wiring
`cmd/cvert-ops/main.go`.

Wiring fact that compounds every finding below: merge and EPSS both run `database/sql` transactions
over a pgxpool opened with `DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol`
(`cmd/cvert-ops/main.go:741`). Simple protocol means **no server-side prepared-statement plan cache** —
every statement is re-parsed and re-planned on each execution. The per-row patterns below therefore pay
parse+plan cost on every one of the 10–20 statements they issue per item.

---

### [CRITICAL] EPSS apply does one full transaction (BEGIN + advisory lock + 2 statements + COMMIT) per CVE row
**Location:** `internal/feed/epss/adapter.go:227` (loop) → `applyRow` at `adapter.go:250-287`; statements `internal/store/queries/cves.sql:124-149` (`UpsertEPSSStaging`, `UpdateCVEEPSS`)
**Problem:** The daily EPSS file is ~250,000 rows. For *each* row the code opens its own
`db.BeginTx`, executes `SELECT pg_advisory_xact_lock($1)`, runs `UpdateCVEEPSS` and `UpsertEPSSStaging`,
then `Commit()`. That is 4 statements + 1 lock acquisition + 1 commit = effectively **5 round-trips and a
COMMIT (fsync) per row**, all serialized in a single goroutine (the worker handler invokes `Apply` once,
which loops synchronously). With simple protocol there is no plan caching, so both DML statements are
re-planned 250k times. Aggregate per daily run: **~250k transactions, ~250k COMMIT fsyncs, ~750k+
statement executions, 250k advisory-lock acquisitions** — for a job whose *steady-state* delta (scores
that actually changed) is a small fraction of rows, because `UpdateCVEEPSS` is guarded by
`epss_score IS DISTINCT FROM $2` and most daily scores are unchanged.
**Impact:** ~5 round-trips + 1 fsync per ingested item × 250k items = the dominant cost of the EPSS feed.
COMMIT-per-row fsync alone bounds throughput to roughly the disk's sequential-fsync rate (single-digit
thousands/sec on typical storage), making a 250k run take minutes-to-tens-of-minutes that is almost
entirely transaction overhead, not useful work. Batching commits (e.g. N rows per tx, or `CopyFrom` into
a temp/unlogged staging table then a single set-based `UPDATE … FROM`/`INSERT … SELECT`) collapses 250k
transactions into tens-to-hundreds and removes the per-row plan cost. The advisory-lock-per-row TOCTOU
requirement (§5.3) is real, but it can be satisfied at batch granularity or by a single set-based apply
under one lock-ordering scheme rather than 250k individual locks.
**Confidence:** Strong-static
**Effort:** Contained + high — the per-row advisory-lock/TOCTOU contract with the merge pipeline (§5.3)
must be preserved; a set-based or chunked rewrite needs a correctness argument and tests, not just a loop
change. Cross-cuts EPSS adapter + the two SQL statements + possibly a staging table.
**Verification plan:** Count statements/transactions per run (instrument `applyRow` call count and tx
count, or `pg_stat_database.xact_commit` delta during one EPSS run) → expect ~250k tx today, target
≤ few hundred after batching. Correctness guard: assert final `cves.epss_score` / `epss_staging` contents
identical between per-row and batched implementations over a golden CSV; assert the advisory-lock
coordination still blocks a concurrent merge for the same CVE (existing `apply_integration_test.go` plus a
race test).

---

### [CRITICAL] Merge re-runs the full multi-statement, advisory-locked pipeline once per patch, with no write batching across a 250k-CVE feed
**Location:** `internal/ingest/handler.go:163-211` (per-patch loop) → `merge.Ingest` `internal/merge/pipeline.go:38-294`
**Problem:** The ingest handler calls `mergeFn(ctx, mergeSt, patch, …)` once per patch, and each call is a
complete `database/sql` transaction containing, at minimum: advisory lock, `UpsertCVESource`,
`InsertCVERawPayload`, `GetAllCVESources`, `UpsertCVE`, `DeleteCVEReferences` + N× `InsertCVEReference`,
`DeleteCVEAffectedPackages` + N× `InsertAffectedPackage`, `DeleteCVEAffectedCPEs` + N× `InsertAffectedCPE`,
`GetEPSSStaging`, `DeleteEPSSStaging`, `UpsertCVESearchIndex`, and COMMIT. That is **~12 fixed statements +
one statement per child row + a COMMIT fsync, per CVE**. For an NVD backfill of 250k CVEs (each with
several references and often dozens of CPEs), this is on the order of **millions of statements and 250k
COMMIT fsyncs**, all under simple protocol (re-planned every time) and all serialized in the single
pagination goroutine. The child-table handling is delete-all-then-insert-row-by-row
(`pipeline.go:188-240`), which is the textbook RBAR write pattern the SQL pack flags — every reference/CPE
is its own round-trip rather than one multi-row `INSERT`/`unnest`/`CopyFrom`.
**Impact:** Per ingested CVE: 1 COMMIT fsync + ~12 + (refs+pkgs+cpes) statement executions. The
delete+per-row-reinsert of children dominates for CPE-heavy NVD records (a CVE with 50 CPEs = 50
round-trips just for CPE inserts, every ingest, even when unchanged). Two cheap wins are independent of
the harder cross-CVE batching: (a) batch each child set into a single multi-row insert
(`INSERT … SELECT * FROM unnest($1,$2,$3)` or `pgx.CopyFrom`), turning N round-trips into 1 per child
table; (b) the merge re-reads + re-resolves + rewrites all children even when the source payload is
byte-identical (`UpsertCVESource` already has an `IS DISTINCT FROM` guard at SQL level, but the pipeline
proceeds through resolve + child rewrite regardless of whether step 2 actually changed anything).
**Confidence:** Strong-static
**Effort:** Cross-cutting + high — the per-CVE advisory lock and full re-resolve are an architectural
contract (§5.1 "recompute from scratch on every source write"). Child-insert batching (win *a*) is
Contained and low-risk; skipping the resolve/rewrite when `UpsertCVESource` was a no-op (win *b*) needs an
explicit changed/unchanged signal out of step 2 and careful correctness review (it must still re-resolve
when *another* source changed the canonical row — but in a single-source backfill that never happens).
**Verification plan:** Instrument statements-per-`Ingest` and COMMIT count over a golden NVD page; show
child-insert round-trips scale with child cardinality today and become O(1) per child table after
batching. Correctness guard: golden-corpus equality of resolved `cves` + child tables before/after; assert
no behavior change for multi-source CVEs (a CVE touched by NVD then GHSA must still re-resolve).

---

### [MAJOR] Realtime alerts add two extra point-read round-trips (pre- and post-merge hash) per merged patch
**Location:** `internal/ingest/handler.go:167-210`; reader `internal/store/cve.go:32` (`GetCVEMaterialHash`)
**Problem:** When the handler is wired with alerts (production: `HandlerWithAlerts` /
`HandlerWithFactoryAndAlerts`, `main.go:186-188`), each patch triggers `GetCVEMaterialHash` *before*
merge and again *after* merge to detect a hash change. These are two separate `SELECT material_hash …`
round-trips **outside** the merge transaction, per CVE. On a 250k NVD backfill that is **500k extra
point reads** purely to discover something the merge transaction already knows: `UpsertCVE`'s
`ON CONFLICT … CASE WHEN cves.material_hash IS DISTINCT FROM EXCLUDED.material_hash` (`cves.sql:21-25`)
already computes whether the hash changed. The information is being recomputed with two client round-trips
instead of being returned from the existing upsert (`RETURNING (xmax<>0) AS updated` or
`RETURNING material_hash` / a changed flag).
**Impact:** +2 round-trips per ingested CVE on the alert-enabled path = ~500k avoidable reads per NVD
backfill, on top of the merge cost above. Returning a "material_hash changed" boolean from `UpsertCVE`
eliminates both reads. (Also note: a backfill of historical CVEs fires realtime alert evaluation for every
changed CVE inline in the pagination loop — separate slice, but it is gated by this same flag.)
**Confidence:** Strong-static
**Effort:** Contained — add `RETURNING` to `UpsertCVE`, thread a `changed bool` out of `merge.Ingest`,
drop the two `GetCVEMaterialHash` calls. Touches merge signature + handler + one query.
**Verification plan:** Count `GetCVEMaterialHash` invocations during an alert-enabled ingest (expect 2×
patches today, 0 after) ; confirm realtime eval still fires on exactly the CVEs whose hash changed
(compare fired set before/after over a golden corpus).

---

### [MAJOR] EPSS staging-drain (`GetEPSSStaging` + `DeleteEPSSStaging`) runs unconditionally inside every merge, even for the overwhelming majority of CVEs that never had a staged score
**Location:** `internal/merge/pipeline.go:262-279`; queries `cves.sql:139-143`
**Problem:** Steps 9 in `Ingest` always issue `GetEPSSStaging` (a SELECT) and `DeleteEPSSStaging` (a
DELETE) for the CVE, regardless of whether a staging row exists. `epss_staging` only holds scores for CVEs
that EPSS saw *before* the CVE was ingested — a small minority. For the other ~99% of CVEs in a backfill,
this is **2 guaranteed round-trips per CVE that find and delete nothing**. The DELETE is harmless
data-wise but is still a planned statement + round-trip per CVE (250k× SELECT + 250k× DELETE on a
backfill). This could be collapsed: a single `DELETE … RETURNING epss_score` replaces the SELECT+DELETE
pair (1 round-trip instead of 2), and even that runs per CVE.
**Impact:** 1 avoidable round-trip per ingested CVE minimum (merge SELECT+DELETE → single DELETE
RETURNING) = ~250k saved on an NVD backfill; the DELETE itself is unavoidable under the current
drain-always contract (pitfall §2.7), so the win is coalescing the read into the delete, not removing it.
**Confidence:** Strong-static
**Effort:** Localized — rewrite `GetEPSSStaging`+`DeleteEPSSStaging` usage as one `DELETE FROM epss_staging
WHERE cve_id=$1 RETURNING epss_score`; apply the returned score if present and not withdrawn.
**Verification plan:** Statement count per `Ingest` drops by 1; correctness guard: staged-then-ingested CVE
still receives its EPSS score and the staging row is gone (existing merge integration test covers the
staging-apply path).

---

### [MINOR] `cve_sources` has no composite index supporting the per-ingest re-read `WHERE cve_id=$1 ORDER BY source_name`
**Location:** `GetAllCVESources` `cves.sql:69-70`; DDL `migrations/000002_create_cve_core.up.sql:77-101`
**Problem:** Step 4 of every merge runs `SELECT * FROM cve_sources WHERE cve_id = $1 ORDER BY source_name`.
The table's PRIMARY KEY is `(cve_id, source_name)` (`:90`), which *does* serve this exactly — equality on
the leading column, sort on the second — so this specific query is fine. Flagging the adjacent real cost:
`GetAllCVESources` is `SELECT *`, which pulls `normalized_json` (jsonb, frequently TOAST-ed and >2 KB for
NVD/OSV) for **every** source row on **every** merge, then `resolve()` parses each. On a single-source
backfill this re-detoasts and re-parses the one source row that was just written — unavoidable given the
re-resolve design, but the `SELECT *` over a wide TOAST-ed jsonb column is the kind of over-fetch the SQL
pack calls out, and it scales with source count for multi-source CVEs.
**Impact:** Per merge: detoast + json-parse of all `normalized_json` blobs for the CVE. No index problem
(PK covers it); the cost is the wide projection of a TOAST-ed column re-read every ingest. Mitigation is
the step-2-no-op short-circuit from the merge CRITICAL above, not an index.
**Confidence:** Strong-static
**Effort:** Localized (but subsumed by the merge finding) — no standalone change recommended beyond the
re-resolve short-circuit.
**Verification plan:** `EXPLAIN (ANALYZE, BUFFERS)` on `GetAllCVESources` for a multi-source CVE; confirm
Index Scan on the PK (no seq scan) and observe `Buffers: … read` from TOAST when `normalized_json` is
large. No new index warranted.

---

### [MINOR] Red Hat adapter is HTTP-N+1 (one list page → one detail GET per CVE) — inherent to the API, out of the large-feed hot path
**Location:** `internal/feed/redhat/adapter.go:429-443`
**Problem:** Phase 2 fetches `cve/{id}.json` once per CVE ID returned by the list page, each behind
`rateLimiter.Wait`. This is a true per-item HTTP round-trip. It is called out for completeness, but the
Red Hat feed is not in the brief's large-feed load profile (NVD/EPSS are), the Red Hat API exposes no
batch-detail endpoint, and the list page bounds the per-cycle CVE count. Not a fix target under the stated
load.
**Impact:** 1 HTTP round-trip per CVE on the Red Hat feed only; bounded by list page size and rate limit.
Not on the 250k hot path.
**Confidence:** Strong-static
**Effort:** Cross-cutting (would require an API change Red Hat doesn't offer) — no action.
**Verification plan:** n/a — documented, not actioned.

---

## Suspected Bugs (for follow-up)

None. (The `GetCVEMaterialHash` double-read is wasteful, not incorrect; the merge/EPSS per-row
transactions are slow, not wrong.)
