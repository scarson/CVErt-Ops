# Feed client body cap fails loudly and fits the bulk archives

## What was built

- `feed.BuildFeedClient`'s body cap returns `feed.ErrBodyTooLarge` when a response is longer than the cap. Before, it ended the body at the cap with a clean EOF.
- `DefaultMaxBodyBytes` is 8 GiB, up from 512 MiB.

## Why

The first full live ingest, run for the version check plan's Phase 2 on 2026-11-10, failed MITRE three times with `mitre: open zip: zip: not a valid zip file`. MITRE's `cvelistV5` archive is 724,684,107 bytes. The 512 MiB cap cut it short without an error, so `DownloadToTemp`'s own size check saw a complete download, and `zip.NewReader` failed on a file with no central directory. OSV's `all.zip` is 2,934,025,989 bytes, so it would fail the same way. The constant's comment said 512 MiB accommodated both archives. That was no longer true.

## Decisions and gotchas

- The cap stays, because it bounds a runaway response. 8 GiB is about twice the OSV archive. `DownloadToTemp` still applies `MaxDownloadSize` (5 GiB) and reports its own overflow, so for archives the smaller bound decides.
- `limitedBody` reads up to the cap, then reads one more byte. If that byte exists, the read fails with `ErrBodyTooLarge`. A body of exactly the cap still reads as complete.
- Not fixed here: the OSV backfill downloads 2.9 GB in every 10-minute job, and the feed client's 5-minute timeout covers the whole body. At the roughly 10 MB/s measured for the MITRE archive, a download takes about 5 minutes, which leaves little of the job for merging. That is a design question for Sam, recorded in the version check plan's Discoveries.

## Quality checks

- `TestMaxBodyTransport_LimitsResponseBody` (now under, at, one over and far over the cap), `TestDownloadToTemp_ReportsBodyOverTransportLimit` and `TestDefaultMaxBodyBytes_FitsBulkArchives` failed before the change and pass after it.
- `go test ./internal/feed/ -count=1` passes. `golangci-lint run ./internal/feed/` reports 0 issues. The full suite result is in the pull request.
