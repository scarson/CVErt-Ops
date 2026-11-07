# OSV backfills resume across jobs, and incremental runs fetch only changed advisories

## What was built

- **Backfill.** A run with a zero cursor reads the newest time in `modified_id.csv`, then reads `all.zip` one page per `Fetch` through `feed.ArchivePager` (`internal/feed/archive.go`), in entry-name order, 1,000 patches a page. The pager keeps the archive between pages of one job, so each job downloads it once. The feed handler checkpoints each page, and its time-limit stop (described in `2026-11-07T0130Z-long-feed-backfills-continue-across-job-limits.md`) ends a run between pages, so a later job resumes after the last entry name read. When the archive is read, the cursor becomes the newest `modified_id.csv` time less a one-hour rescan window.
- **Incremental runs.** A run with a non-zero cursor streams `modified_id.csv`, stops at the first line at or before the cursor, and fetches only the listed advisories from `<ecosystem>/<id>.json`, rate-limited to 20 a second, in pages of 1,000 in key order. A pass reads changes up to the newest time it saw when it began (`snapshot`). An advisory that changes again during the pass moves past the snapshot and is left to the next pass, which starts from the snapshot less the rescan window. An advisory listed but missing from the bucket is skipped with a warning; any other failed fetch fails the run so the page is retried.
- `osv.Cursor` is `{"last_modified", "snapshot", "after"}`. Between passes only `last_modified` is set, the same shape as before.
- The OSV adapter implements `io.Closer`, and the handler closes any adapter that implements it when the run ends, so a run stopped part-way does not leave the downloaded archive behind. A close error is logged and does not change the recorded outcome.
- MITRE pages with its own walk by `dateUpdated`, described in `2026-11-07T2137Z-mitre-feed-walks-changed-records-in-resumable-pages.md`. `feed.ArchivePager` is used by OSV only.

## Key decisions

- **`modified_id.csv` names the changes; `all.zip` entry times do not.** OSV documents the bucket layout at https://google.github.io/osv.dev/data/: `modified_id.csv` at the bucket root and in each ecosystem directory, lines `<iso modified date>,<ecosystem_dir>/<id>` (per-ecosystem files omit the directory), "sorted in reverse chronological order", so a reader can stop at a timestamp it has already seen; records at `<ECOSYSTEM>/<ID>.json`. Checked on 2026-11-07 with real requests: the root file is 157 MB with no header line and times in RFC 3339 with nanoseconds (for example `2026-11-07T21:00:07.402189265Z,Debian/DEBIAN-CVE-2026-76181`); a record fetch such as `crates.io/RUSTSEC-2026-0453.json` returns the advisory JSON.
- **The root file, not per-ecosystem files.** It covers the same advisories as `all.zip`, so the backfill and incremental runs read the same set.
- **The backfill reads `modified_id.csv` before downloading `all.zip`.** Its newest time bounds what the archive must already contain; the rescan window covers the archive being exported a little behind the list.
- **A one-hour rescan window.** The list is exported separately from the advisories, so an advisory can appear after one with a later time. Re-reading the last hour costs a few hundred to a few thousand fetches a day. The MITRE adapter uses the same window for the same reason.
- **One page size for both kinds of run.** At 20 fetches a second a 1,000-advisory page takes 50 seconds to fetch and about 77 to merge, inside the handler's 3-minute page reserve.
- **`ArchivePager` pages by name only.** An earlier version of this change filtered entries by their ZIP modified time and ended a pass at the archive's newest entry time. OSV's entries all carry MS-DOS time 0, so that filter has no user, and the pager was reduced to name-ordered paging.
- The handler's empty-page stop is unchanged. A non-final page of either kind holds at least one advisory unless every advisory on it is missing from the bucket or unreadable.

## Gotchas

- OSV's `all.zip` stamps every entry with MS-DOS date and time 0, which Go reads as a fixed date in 1979. Checked on 2026-11-07: every entry of the crates.io export (3,055) and all 13,391 central-directory entries in the last 1 MB of `all.zip`. The adapter on dev filtered on those times with a download-time cursor, so every run after a first backfill selected nothing.
- `all.zip` is 2.9 GB with 2,368,300 entries (from its ZIP64 end record). A backfill at about 13 merges a second is about 50 hours, roughly 300 jobs, each downloading the archive once. Re-reading the archive on every run would download about 900 GB a pass, which is why incremental runs use the list.
- About 19,000 advisories changed in the 24 hours before 2026-11-07T21:00Z; some days in the preceding week were several times that. At about 2.5 KB each, a day's incremental run downloads tens of megabytes.
- `modified_id.csv` is 157 MB. An incremental run reads only its head, down to the cursor, and closes the connection.
- `sort` order is byte order, so `PyPI/` sorts before `[EMPTY]/` and `npm/`. The `[EMPTY]` directory holds advisories with no ecosystem; object names are path-escaped per segment.

## Known limits

- A cursor far in the past makes an incremental run hold every changed key since then in memory and re-read that part of `modified_id.csv` once per page. After a long outage, clearing the cursor to rerun the backfill is cheaper.
- The pager depends on `all.zip`'s entry names staying stable between jobs.
- EPSS still applies its whole file in one call, as before.

## Quality checks

- New tests failed before each change (missing types, fields and methods; the handler did not close adapters) and pass after it.
- `internal/feed/osv/changes_test.go`, against a fake bucket that counts requests per path: the backfill end point and resume, an incremental run with three changes making three record fetches and no `all.zip` download, early stop in `modified_id.csv`, a malformed line, nothing new, an incremental pass resumed across jobs with changes after the snapshot left to the next pass, and a missing versus failing record fetch.
- `internal/feed/archive_test.go`: page slicing, resume in a new job, an upstream archive change between jobs, duplicate names, temp-file removal, a new read while an archive is held, page size, and a download error.
- `internal/ingest/handler_archive_test.go` drives the real OSV adapter through the handler: a 1,001-entry backfill stops after one page at the time limit, the next job finishes it and every advisory merges once, and the following run fetches only the changed advisory and the one inside the rescan window, without downloading `all.zip`.
- The OSV golden test and `SeedCorpus` now serve a one-line `modified_id.csv` beside the golden `all.zip`.
- `golangci-lint run ./internal/feed/... ./internal/ingest/... ./internal/testutil/...` reports 0 issues. The full suite result is recorded in the pull request.
- Not run against the live OSV bucket.
