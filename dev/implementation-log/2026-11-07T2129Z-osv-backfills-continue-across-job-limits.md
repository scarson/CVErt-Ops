# OSV backfills continue across job limits

## What was built

- `feed.ArchivePager` in `internal/feed/archive.go` returns a downloaded ZIP archive's record entries in pages of `feed.ArchivePageSize` (1,000) patches, in entry-name order. The OSV adapter delegates `Fetch` to it, so the feed handler checkpoints each page and its time-limit stop (described in `2026-11-07T0130Z-long-feed-backfills-continue-across-job-limits.md`) applies to OSV too. MITRE pages with its own walk by `dateUpdated`, described in `2026-11-07T2137Z-mitre-feed-walks-changed-records-in-resumable-pages.md`.
- `feed.ArchiveCursor` replaces the OSV adapter's own `Cursor` type. Between passes it is `{"last_modified": T}`, the same shape as before, so stored cursors need no migration. During a pass it adds `pass_started_at` (download time of the archive that began the pass) and `resume_after` (last entry name of the last completed page).
- Within one job the pager keeps the archive between pages, so a job downloads it once. It removes the temp file when the pass ends. The OSV adapter implements `io.Closer`, and the handler closes any adapter that implements it when the run ends, so a run stopped part-way does not leave the download behind. A close error is logged and does not change the recorded outcome.

## Key decisions

- **Resume by entry name, not by position.** A later job downloads the current archive, which may have gained or lost entries. Names are stable across versions; indexes are not.
- **The final cursor is the pass start time, not the last download time.** An entry that changed upstream after the pass began, behind the resume key, is not read in the resumed pass. Its modified time is after the pass start, so the next pass reads it. Entries changed ahead of the key are read in both passes, which the merge pipeline tolerates.
- **Each mid-pass page keeps the pass's baseline.** An incremental pass split across jobs still skips entries at or before its original `last_modified`.
- **Entries with the same name stay on one page.** The next page starts after a name, so a duplicate left on the far side of a page boundary would be skipped.
- **Page size 1,000.** At the roughly 13 CVEs per second measured on the NVD backfill, a page merges in about 80 seconds, well inside the handler's 3-minute page reserve. The first page of each job also pays for the download, which happens before the reserve check.
- The handler's empty-page stop is unchanged. A non-final archive page always holds at least one patch, so it never reaches that stop.

## Gotchas

- The pager's pre-filter relies on each entry's `FileHeader.Modified` reflecting when that record changed. GitHub archive downloads stamp every entry with the head commit's time (checked on a small GitHub repository archive: 103 entries, one distinct modified time), which is why MITRE filters on `dateUpdated` instead. Whether OSV's `all.zip` carries per-record times has not been checked; if it does not, every OSV run is a full pass, which now finishes across jobs instead of never finishing.
- Each job of a pass downloads the archive again, since a job's temp file is gone when the job ends.
- `sort` order is byte order, so OSV's `PyPI/` sorts before `npm/`.

## Known limits

- The pager depends on the archive's entry names staying stable between jobs.
- EPSS still applies its whole file in one call, as before.

## Quality checks

- New tests failed before the change (missing types and methods; the handler did not close adapters) and pass after it.
- `internal/feed/archive_test.go` covers page slicing, resume in a new job, an upstream archive change between jobs with nothing missed by the next pass, the baseline on resumed pages, an incremental run with nothing new, duplicate names, temp-file removal, a new pass while an archive is held, a malformed resume cursor, the older cursor shape, and a download error.
- `internal/ingest/handler_archive_test.go` drives the real OSV adapter through the handler for 1,001 entries: the first job stops after one page at the time limit, the second resumes and finishes, every advisory merges once, and the final cursor is the pass start.
- Full `go test ./... -count=1 -timeout=600s` with `TESTCONTAINERS_RYUK_DISABLED=true` (the known reaper `removing` failure on this host). Results are in the pull request.
- `golangci-lint run ./internal/feed/... ./internal/ingest/...` reports 0 issues.
- Not run against the live OSV archive.
