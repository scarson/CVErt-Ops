# Feed handler closes the MITRE adapter

## What was built

- `mitre.Adapter.Close` returns an error, which is always nil, so the adapter implements `io.Closer`. The feed handler closes any adapter that implements it when a run ends (`internal/ingest/handler.go`). That hook arrived with the OSV archive paging (`2026-11-07T2129Z-osv-backfills-resume-and-incremental-runs-fetch-changed-advisories.md`).
- MITRE pages use `feed.ArchivePageSize`, the page size OSV uses, instead of a constant of its own with the same value, 1,000.

## Key decisions

- The adapter still removes its archive on the walk's last page and when the context of the downloading `Fetch` ends. The handler's close makes the removal happen at the end of every run, without waiting on a goroutine started by the context ending. The context path remains for callers that never close the adapter, such as `testutil.SeedCorpus`.

## Quality checks

- `TestNew_IsCloserWithArchivePageSize` failed before the change, because the adapter was not an `io.Closer`, and passes after it.
- `go test ./internal/feed/mitre/ -race -count=1` passes, `go vet ./internal/...` is clean, and `golangci-lint run ./internal/feed/... ./internal/ingest/...` reports 0 issues.
