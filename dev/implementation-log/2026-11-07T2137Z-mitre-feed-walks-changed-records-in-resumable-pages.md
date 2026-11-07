# MITRE feed walks changed records in resumable pages

## What was built

- `internal/feed/mitre` selects records by `cveMetadata.dateUpdated` instead of the ZIP entry's modified time, and returns them in pages of 1,000 in CVE ID order.
- The cursor gains two fields for a walk in progress: `after`, the CVE ID of the last record returned, and `snapshot`, the latest `dateUpdated` in the archive the walk started on. The last page returns `{"last_modified": snapshot - 1h}`. An existing `{"last_modified": T}` cursor reads as "records updated after T".
- An adapter downloads the archive once per job and keeps it between pages (`archive.go`). It removes the temp file on the last page, on `Close`, or when the context of the downloading `Fetch` ends, which for the ingest handler is the end of the job (`context.AfterFunc`).
- The selection pass decodes each entry only as far as `cveMetadata` and reads only entries whose CVE ID sorts after `after`. A skipped unreadable record is logged as a warning through an injectable logger.
- FEED-7 in `dev/implementation-pitfalls.md` now says that the ZIP-time pre-filter needs per-entry change times, which the cvelistV5 archive does not have.

## Key decisions

- **The walk ends at the start archive's latest `dateUpdated`, not at the wall clock or the end archive.** A walk can span many jobs, and each job reads the archive current at that time. A record the walk has already passed, or a new record that sorts before `after`, changes after the start archive was built, so its `dateUpdated` is later than everything in that archive. The next walk therefore selects it. Ending at the wall clock would skip records stamped between the commit and the download.
- **One-hour rescan window.** `dateUpdated` is stamped upstream before the record reaches the archive, so arrival order can differ from stamp order. On the real archive about 5 records fell in the last hour, and 794 in the last 24 hours, so the window costs a few dozen repeated merges, which change nothing.
- **Order by CVE ID, not archive path.** The position survives a change of directory layout or top-level folder name. Any total order works, because the cursor only needs `id > after`.
- **No archive reuse across jobs.** A first backfill downloads the archive once per job. Keeping it between jobs would need process-level state that outlives the job and its cleanup.
- **A non-last page is always full.** The page loop skips unreadable records and keeps reading until it has 1,000 patches. The ingest handler treats an empty page as the end of the feed.

## Measurements on the real archive

These were taken on this Windows host on 2026-11-07, from commit `b194b6d` of cvelistV5: 722,767,821 bytes and 420,947 CVE records.

- Every CVE entry carries the same modified time (21:10:52Z, the commit time), so the old pre-filter selected every entry or none. The latest `dateUpdated` was 21:04:27Z, and every record had one.
- The download took 66 s. A full metadata pass took 27 s with the stop-early decoder and 46 s with a full parse; 194,140 records put `containers` before `cveMetadata`.
- The adapter alone, without merging, walked all records in 421 pages in 84 s. The first page took 28 s, later pages under 0.75 s, and peak heap was 299 MB. A new job resuming halfway returned its first page in 14.6 s. An incremental walk from 24 hours before the snapshot returned 794 records in 38 s.
- Records updated per day over the last two weeks: 739 to 2,783. 10,635 changed in 7 days, and 31,973 in 30 days.

## Run cost estimates

These use the 13 merges a second measured on the NVD backfill. MITRE merge speed has not been measured.

- **First run:** 420,947 merges take about 9 hours. A 10-minute job spends about 66 s downloading, up to 28 s selecting, and about 78 s per page. The handler starts no page with under 3 minutes left, so a job merges about 5,000 records. That is about 85 jobs and 13 hours of wall time, with each job starting on the scheduler tick after the previous one. It downloads about 61 GB from GitHub in total.
- **Daily run:** one job. It downloads (66 s), selects (27 s), and merges 800 to 2,800 records (1 to 4 minutes), so about 3 to 5 minutes in all.

## Behaviour when a job is cut off

- The handler saves the cursor after every completed page. A job stopped between pages by the time limit is recorded as `partial`, and the scheduler starts the next job on its next tick. That job downloads the then-current archive, selects records after `after` that were updated after `last_modified`, and continues. `snapshot` stays the value from the first job.
- A deadline in the middle of a page loses that page's progress, and the next job repeats it (up to 1,000 merges).
- A job that cannot finish its first page, such as a download longer than the job limit, makes no progress and is recorded as a failure with backoff, as before.

## Known limits

- A record whose ADP or CNA container changes without a change to `cveMetadata.dateUpdated` is not seen as changed. The real archive had at most four such records, all from 2024. A first run fetches them.
- Merge throughput for MITRE pages is estimated, not measured; no dev database or deployment was reachable. The dev Compose Postgres fails to start because its volume holds a pre-18 data directory under the Postgres 18 image.

## Quality checks

- New tests in `walk_test.go`, the reworked `TestFetch_IncrementalSkipsOldEntries`, and `TestFetch_GoldenIncrementalReturnsRecordsUpdatedAfterCursor` (real records, one entry time) failed before the change and pass after it.
- `go test ./internal/feed/mitre/ -race -count=1` passes, and `golangci-lint run ./internal/feed/...` is clean.
- `TestMaterialHash_GoldenCorpusMatchesPins` in `internal/merge` passes with `golden_material_hashes.json` unedited, run with `TESTCONTAINERS_RYUK_DISABLED=true`.
- The real-archive measurements came from a throwaway test that served the downloaded ZIP locally. It is not committed.
