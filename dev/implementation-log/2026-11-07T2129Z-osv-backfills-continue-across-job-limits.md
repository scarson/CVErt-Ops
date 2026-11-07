# OSV backfills continue across job limits

## What was built

- `feed.ArchivePager` in `internal/feed/archive.go` returns a downloaded ZIP archive's record entries in pages of `feed.ArchivePageSize` (1,000) patches, in entry-name order. The OSV adapter delegates `Fetch` to it, so the feed handler checkpoints each page and its time-limit stop (described in `2026-11-07T0130Z-long-feed-backfills-continue-across-job-limits.md`) applies to OSV too. MITRE pages with its own walk by `dateUpdated`, described in `2026-11-07T2137Z-mitre-feed-walks-changed-records-in-resumable-pages.md`.
- `feed.ArchiveCursor` replaces the OSV adapter's own `Cursor` type. Between passes it is `{"last_modified": T}`, the same shape as before, so stored cursors need no migration. During a pass it adds `snapshot` (the latest record modified time in the archive that began the pass) and `resume_after` (last entry name of the last completed page).
- Within one job the pager keeps the archive between pages, so a job downloads it once. It removes the temp file when the pass ends. The OSV adapter implements `io.Closer`, and the handler closes any adapter that implements it when the run ends, so a run stopped part-way does not leave the download behind. A close error is logged and does not change the recorded outcome.

## Key decisions

- **Resume by entry name, not by position.** A later job downloads the current archive, which may have gained or lost entries. Names are stable across versions; indexes are not.
- **A pass ends at the starting archive's latest record time, less one ZIP time step (2 seconds), not at the download time.** An archive is generated before it is downloaded. A record changed in that gap is missing from the archive but stamped before the download, so a download-time cursor would skip it on every later pass. The 2-second step is the MS-DOS time resolution: a record changed in the same step as the archive's newest one is read again rather than missed. Changes made upstream while a pass spans several jobs, including entries behind the resume key, have later times and are read by the next pass.
- **The next baseline can move back.** A stored cursor from before this change holds a download time, which is later than every entry in OSV's archive. Ending the pass at the archive's own times lets the next pass read the archive instead of skipping it forever.
- **Each mid-pass page keeps the pass's baseline.** An incremental pass split across jobs still skips entries at or before its original `last_modified`.
- **Entries with the same name stay on one page.** The next page starts after a name, so a duplicate left on the far side of a page boundary would be skipped.
- **Page size 1,000.** At the roughly 13 CVEs per second measured on the NVD backfill, a page merges in about 80 seconds, well inside the handler's 3-minute page reserve. The first page of each job also pays for the download, which happens before the reserve check.
- The handler's empty-page stop is unchanged. A non-final archive page always holds at least one patch, so it never reaches that stop.

## Gotchas

- OSV's `all.zip` stamps every entry with MS-DOS date and time 0, which Go reads as a fixed date in 1979. Checked on 2026-11-07: every entry of the crates.io export (3,055) and all 13,391 central-directory entries in the last 1 MB of `all.zip`. The `FileHeader.Modified` pre-filter therefore selects every entry or none. Before this change the cursor was the download time, so every OSV run after a first backfill selected nothing and OSV stopped updating; with this change every pass reads the whole archive.
- `all.zip` is 2.9 GB with 2,368,300 entries (from its ZIP64 end record). At about 13 merges a second a full pass is about 50 hours, roughly 300 jobs, and each job downloads the archive again. With OSV's 24-hour interval, passes run back to back.
- GitHub archive downloads have the same problem: every entry carries the head commit's time. That is why MITRE filters on `cveMetadata.dateUpdated` instead of using this pager.
- `sort` order is byte order, so `PyPI/` sorts before `npm/`.

## Known limits

- OSV needs an incremental source that names changed records, such as the bucket's `modified_id.csv`, before its runs are cheap. Until then each pass reads and downloads the whole archive.
- The pager depends on the archive's entry names staying stable between jobs.
- EPSS still applies its whole file in one call, as before.

## Quality checks

- New tests failed before each change (missing types, fields and methods; the handler did not close adapters) and pass after it.
- `internal/feed/archive_test.go` covers page slicing, resume in a new job, an upstream archive change between jobs with nothing missed by the next pass, a record changed between archive generation and download, an archive with no records, a baseline later than every entry time, the baseline on resumed pages, an incremental run with nothing new, duplicate names, temp-file removal, a new pass while an archive is held, a malformed resume cursor, the older cursor shape, and a download error.
- `internal/ingest/handler_archive_test.go` drives the real OSV adapter through the handler for 1,001 entries: the first job stops after one page at the time limit, the second resumes and finishes, every advisory merges once, and the final cursor sits just before the pass's snapshot.
- `go test ./internal/feed/ ./internal/feed/osv/ ./internal/ingest/ ./internal/testutil/ -count=1` passes with `TESTCONTAINERS_RYUK_DISABLED=true` (the known reaper `removing` failure on this host). `golangci-lint run ./internal/feed/... ./internal/ingest/...` reports 0 issues.
- Full `go test ./... -count=1 -timeout=600s` at the merge of dev (797b2b1, before the snapshot change): every package passed except three `internal/store` delivery-claim tests, which passed when the package ran alone. An earlier full run had the same symptom in `internal/notify` (`TestWorker_RefusedDestinationWithheldFromOrg`), which also passed alone. Neither package is touched here.
- Not run against the live OSV archive.
