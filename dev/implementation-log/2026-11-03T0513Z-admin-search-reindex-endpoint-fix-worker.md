# Admin Search Reindex — Endpoint Fix + Worker

> **Date:** 2026-11-02
> **Commits:** `b505bb4`, `b57226e` on `fix/admin-reindex` (branched from `dev` at `2dcffc8`)
> **Spec:** PLAN.md §17 (admin actions: rebuild search index); `dev/plans/2026-03-10-phase8-ops-operate-design.md` (System section: `POST /api/v1/admin/reindex`, 202 async via job queue)

## What was built

| Feature | Files | Description |
|---|---|---|
| Enqueue fix | `internal/api/admin_system.go` | Enqueues `{}` instead of a nil payload (`job_queue.payload` is NOT NULL, so every call had returned 500) on `merge.SearchReindexQueue` |
| Search index rebuild | `internal/merge/reindex.go` | `RebuildSearchIndex(ctx, store, batchSize)`: keyset walk over `cves` by `cve_id`; per batch, one transaction takes the merge advisory locks, reads inputs, reruns `UpsertCVESearchIndex` |
| Rebuild queries | `internal/store/queries/cves.sql` | `ListCVEIDsAfter`, `LockCVEAdvisoryKeys` (ascending key order), `ListSearchIndexInputs` (description, CWE IDs, raw package names) |
| Worker handler | `cmd/cvert-ops/main.go` | `searchReindexHandler` on `system_reindex`, batch size 200; `registerMaintenanceJobs` registers it and `retention_cleanup` for both `serve` and `worker` |
| Sorted FTS package names | `internal/merge/pipeline.go` | `ftsPackageNames` de-duplicates and sorts package names bytewise for both merge and the rebuild, as PLAN.md §5.3 requires for arrays in the FTS document |
| Job outcome after deadline | `internal/worker/pool.go` | `processOne` records `CompleteJob`/`FailJob` on a context detached from the job's (10 s `recordOutcomeTimeout`) |

## Key implementation decisions

- **Implement rather than remove** — Sam chose to keep the endpoint because PLAN.md §17 lists "rebuild search index" as an MVP admin action. Merge already rewrites the FTS row on every ingest, so a rebuild is needed only when the tsvector recipe changes or rows were written outside merge.
- **Reuse the merge tsvector recipe** — the rebuild calls the generated `UpsertCVESearchIndex`, so the weighting (A description, B CWE IDs, C package names, D CVE ID) has one definition. A set-based `INSERT ... SELECT` would have been faster but would duplicate the recipe in SQL.
- **Advisory locks before the read** — each batch transaction locks every CVE's `merge.CVEAdvisoryKey` before it reads. Under READ COMMITTED the read sees every merge that committed before the locks were granted, so the rebuild never writes a tsvector built from pre-merge text. Merge's late-binding PK migration takes the destination lock and then the source lock, out of key order, so a batch holding the source and waiting on the destination deadlocks with it. Postgres aborts one transaction; when it aborts the batch, the rebuild retries that batch (up to `maxBatchAttempts` = 3, only on SQLSTATE 40P01).
- **Batch size 200** — per-CVE transactions would cost ~6 round trips per CVE and could exceed the 10-minute `maxJobDuration` on a full corpus. Batches keep a few hundred statements per transaction while holding at most 200 advisory locks at a time, well under the shared lock table (`max_locks_per_transaction` × connections). Measured throughput: 20k synthetic CVEs (NVD-length descriptions, 2 packages each) in 8.7 s, 0.43 ms/CVE, so ~2 m 10 s for 300k CVEs, inside the 10-minute cap with a 4.6× margin. The rebuild does not resume across attempts; if the corpus grows past that margin, it needs a persisted cursor or set-based upserts.
- **Package names sorted in Go, not SQL** — an `ORDER BY` in `ListSearchIndexInputs` follows the database collation, so under a linguistic collation (`en-US-x-icu`) "alpha" sorts before "Zebra" while merge's bytewise sort puts "Zebra" first, and the rebuild would move lexeme positions. Both paths go through `ftsPackageNames`.
- **Shared queue constant** — `merge.SearchReindexQueue` is used by the API enqueue and both worker registrations. The original bug was an enqueue with no consumer.

## Gotchas discovered

- **Package-name order made the FTS document unstable** — `collectPackageNames` kept feed insertion order, so a feed reordering its affected packages changed tsvector positions, and a rebuild from `cve_affected_packages` could not reproduce merge's document. Sorting fixes both. Existing rows pick up the sorted form on their next merge or on a rebuild.
- **`sqlc generate` on Windows touches every generated file** — with `core.autocrlf=true` the checkout is CRLF and sqlc writes LF. Only `cves.sql.go` had content changes; the rest were restored with `git restore -- internal/store/generated ':!internal/store/generated/cves.sql.go'`.
- **OpenAPI spec documents 200, not 202** — no operation in `openapi_spec.go` sets `DefaultStatus`, so every 202 endpoint (reindex, feed trigger, ingest, invitations, alert-rule activation) is documented as 200. Fixed on a separate branch, `fix/openapi-async-status`.
- **The worker pool lost job outcomes at the deadline** — `processOne` called `FailJob`/`CompleteJob` with the job's own context. A handler that ran to `maxJobDuration` left the job `running`, the status write failed with `context deadline exceeded`, and stale recovery requeued it after 10 minutes regardless of `max_attempts`. For the reindex job that meant a restart loop holding `system:reindex`, so every admin call returned 409. Found by the codex review; fixed in the pool for all queues.
- **Stale recovery ignores `max_attempts`** — `RecoverStaleJobs` resets any job stuck in `running` to `pending` without checking attempts, so a job that crashes its worker every time is retried forever. Not changed here.
- **`internal/api` exceeds the 600 s package timeout** — 650 tests each start their own Postgres container. On this machine the package took 1112 s when run alone (with 55 other containers on the daemon), so `go test ./... -timeout=600s` always fails there. A test binary killed by the timeout panic skips `t.Cleanup`, and with `TESTCONTAINERS_RYUK_DISABLED=true` its containers stay running.

## Quality checks

- **go build ./...:** Clean
- **golangci-lint run ./internal/merge/... ./internal/worker/... ./internal/api/... ./cmd/...:** 0 issues
- **Tests:** full suite at `fad0ed0`: 33 packages pass, `internal/api` timed out at 600 s. At `b57226e` (review fixes): `internal/merge`, `internal/worker`, `internal/ingest`, `cmd/cvert-ops` pass; `internal/api` passes with `-timeout=45m` (1112 s).
- **Review:** `codex exec` (gpt-6.1-sol, high) found three medium issues, each reproduced: rebuild progress lost at the job deadline (root cause in the worker pool, fixed there), package order following the database collation (fixed), and a deadlock with merge's PK migration aborting the rebuild (fixed with a batch retry). It also noted that the end-to-end test registered its own handler (fixed with `registerMaintenanceJobs`).
- **New tests:** `TestAdminReindex_EnqueuesSearchReindexJob` (202, job on the consumed queue, 409 on repeat — failed with 500 before the fix), `TestAdminReindex_RequiresSiteAdmin`, `TestRebuildSearchIndex_RestoresMissingAndStaleRows` (batch boundary, missing + stale rows match merge output), `TestRebuildSearchIndex_EmptyCorpus`, `TestRebuildSearchIndex_WaitsForMergeLock`, `TestSearchReindexJob_RunsAndRebuildsIndex` (enqueue → `worker.Pool` with the production registrations → job `succeeded` → row rebuilt), `TestCollectPackageNames/sorted_lexicographically`, `TestRebuildSearchIndex_PackageOrderIgnoresCollation` (`en-US-x-icu` column), `TestRebuildSearchIndex_RetriesBatchAfterDeadlock` (deterministic lock cycle from a second session), `TestProcessOne_HandlerTimesOut_JobRecordedDead`, `TestProcessOne_HandlerSucceedsAtDeadline_JobRecordedSucceeded`
