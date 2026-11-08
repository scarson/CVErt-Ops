# EPSS daily apply fits the job limit

## What was built

- `epss.Adapter.Apply` applies the daily file in batches of 500 rows (`defaultBatchSize`). Each batch is one transaction: `LockCVEAdvisoryKeys` takes the merge advisory lock (`merge.CVEAdvisoryKey`) for every CVE in the batch in ascending key order, then the two-statement EPSS pattern runs as set-based statements, `UpdateCVEEPSSBatch` and `UpsertEPSSStagingBatch` in `internal/store/queries/cves.sql`. Both keep their `IS DISTINCT FROM` guards, both run on every batch, and `RowsAffected` is never read (PLAN.md §5.3).
- A batch that fails for any reason other than the end of the job context is applied row by row with the existing `applyRow`, so a row the database rejects costs only that row, as before.
- `latestScores` reduces a batch to one score per CVE ID, the last one in the batch. `ON CONFLICT DO UPDATE` cannot change one row twice in a statement, and the last score is what applying the rows in file order gives.
- `Apply` reads the whole compressed file into memory (capped at the existing 50 MB limit) before applying any row, and still parses the CSV as a stream.

## Measurements

Measured on Postgres 18 (`postgres:18-alpine` in Docker Desktop on Windows) with durable settings (`fsync=on`, `synchronous_commit=on`, `full_page_writes=on`), not the test cluster's `fsync=off`. The corpus is 290,000 `cves` rows; the file has 300,000 rows, 10,000 of them for CVEs not yet in `cves`. The current EPSS file has about 250,000–300,000 rows (1.5 MB compressed for the synthetic 300,000-row file).

| Apply | Per-row transactions (before) | Batches of 500 (after) |
|---|---|---|
| 300,000 rows, every score new | 22 m 10 s (226 rows/s) | 8.1 s |
| 300,000 rows, 99.5% of scores changed (rounding to five decimals leaves 0.5% equal) | ≈19–25 min (extrapolated from 20,000 rows at 233 rows/s) | 8.4 s |
| 300,000 rows, no score changed | ≈19 min (extrapolated from 20,000 rows at 268 rows/s) | 3.5 s |

Before the change, a full file needed more than twice the 10-minute job limit, and more than four times the 5-minute feed client timeout that also applied (see Key decisions). Every run failed, and because each attempt restarted at the first row, the rows past roughly the first 70,000 were never applied. After the change, a full file took 8.1 seconds in this run, and 61 seconds in an independent rerun of the same harness on the same host while other sessions were using Docker. That is between 1.4% and 10% of the job limit. These timings apply to this host and synthetic file.

The harness was a test that started its own durable container, seeded `cves` with one `INSERT ... SELECT unnest(...)`, served a generated file through `httptest`, and timed `Apply`.

## Key decisions

- Batching, without a resumable row position. The batched apply finishes a full-size file in a small fraction of the job limit, so a resume position would add cursor state and a partial-run path for no benefit today. A resume position would also not work as things stand: the adapter's 24-hour rate limiter refuses a second download in the same process, so a retried job cannot fetch the file again (see Known limits).
- The locking strategy follows the recommendation recorded in `docs/plans/2026-06-05-whole-repo-perf-audit-remediation-plan.md` (appendix entry "EPSS batch-apply locking strategy": chunked batches that keep the per-CVE locks, not a staging-table set-apply with a new locking discipline). It reuses the locking that `merge.RebuildSearchIndex` already uses for its batches.
- 500 rows per batch. Each CVE in a batch holds one advisory lock until commit, and advisory locks use the shared lock table (`max_locks_per_transaction` × `max_connections`, 6,400 with Postgres defaults). The search index rebuild uses 200 for the same reason. 500 keeps one batch under a tenth of the table.
- Deadlocks are not retried in a loop. Merge's late-binding PK migration takes a second lock out of key order, so a batch can deadlock with it. Postgres aborts one transaction; if it aborts the batch, the row-by-row fallback applies those rows holding one lock at a time, which cannot deadlock with merge.
- A CVE listed twice in one batch gets its last score, but the batch does not repeat the intermediate writes. With a stored score of 0.5 and rows 0.6 then 0.5, row-by-row writes would move `date_epss_updated`, and an existing staging row's `as_of_date` and `ingested_at`; the batch leaves them alone. The final score is the same, and the batch treats the row as the unchanged score it is. The golden fixture lists each CVE once, so splitting batches around repeated IDs would add code for input not seen in the feed.
- The download is buffered because `feed.BuildFeedClient` sets `http.Client.Timeout` (300 seconds for EPSS), and that timeout covers reading the body. When rows were applied while the body streamed in, the effective limit on the apply was 5 minutes, not the 10-minute job limit.

## Gotchas

- sqlc 1.30 does not know the two-argument `unnest(a, b)` and fails with `function unnest(unknown, unknown) does not exist`. The queries use two single-array `unnest` calls in a select list, which Postgres runs in lockstep; `watchlist.sql` already uses that form.
- The concurrent first-ingest test (`TestApply_ConcurrentFirstIngestKeepsScore`) passes with the advisory locks removed: the race window between the two statements is too narrow to hit. `TestApply_WaitsForMergeAdvisoryLock` is the test that fails without the locks; both were break-tested.

## Known limits

- The adapter's rate limiter (`rate.Every(24*time.Hour)`, burst 1) refuses a second download in the same process for 24 hours, and `Apply` caps the wait at 5 minutes, so it fails at once. Any failed EPSS run (a network error, a database outage) therefore cannot be retried by the job's later attempts or by the scheduler until a day after the first download. It is a separate fix.
- The measurements come from Docker Desktop on Windows, where each round trip to the container is slow. A Linux host with a local database should be faster for both versions; the ratio between them is the reliable result.

## Quality checks

- New unit tests failed before the change (no batch hook) and pass after it. `TestApply_SlowApplyDoesNotHitClientTimeout` was break-tested against the streaming download and failed with `read csv row: context deadline exceeded (Client.Timeout or context cancellation while reading body)`.
- An independent executing review found that the row-by-row fallback hid a broken `applyBatch`: with `applyBatch` always returning an error, every test still passed. The integration helper `applyFile` now fails on any logged warning, and `TestApply_FileLongerThanOneBatch` applies 1,201 rows through the real batch path. With the same break, `TestApply_WritesKnownCVEsAndStagesUnknownCVEs`, `TestApply_UnchangedScoreKeepsUpdateTime` and `TestApply_FileLongerThanOneBatch` fail.
- `TestApply_UnchangedScoreKeepsUpdateTime` covers an unchanged staged score. It failed with the `IS DISTINCT FROM` guard removed from `UpsertEPSSStagingBatch`, with `unchanged staged score was rewritten`.
- `TestApply_RowRejectedByDatabaseCostsOnlyThatRow` makes Postgres reject one row through a CHECK constraint and confirms the rest of its batch lands through the row-by-row path.
- `TestApply_WaitsForMergeAdvisoryLock` was break-tested with the lock call given no keys and failed with "Apply finished while the merge lock was held".
- `go test ./internal/feed/epss/ -count=1` passes with a real Postgres (`TESTCONTAINERS_RYUK_DISABLED=true`, because of the known reaper `removing` failure on this host), including the golden file test.
- `golangci-lint run` is clean on `internal/feed/epss/...` and `internal/store/...`. `pitfall-check` found no issues.
- The measurement harness was not committed: it seeds `cves` with raw SQL, which the testing rules forbid for tests. Only the EPSS write path is measured, and it does not read `material_hash`, child tables or the search index.
