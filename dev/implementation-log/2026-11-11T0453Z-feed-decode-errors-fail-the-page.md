# Feed decode errors fail the page instead of looping

## What was built

- The NVD, GHSA and KEV stream parsers skip a record only when `Decode` returns a `*json.UnmarshalTypeError`. Any other error, other than a syntax error, now fails the page with the decode error wrapped (`decode vulnerability`, `ghsa: decode advisory`).
- FEED-1 in `dev/implementation-pitfalls.md` now names the failure and the one safe exception, and its checklist line says the same.

## Why

The full live ingest for the version check plan's Phase 2 stopped making progress at 17:31 UTC on 2026-11-10 and stayed stuck for 11 hours. An NVD page request ended early: the page that failed and its neighbours measured 6 to 10 MB, far under the parser's 50 MB limit, so the connection most likely closed partway through the body. `Decode` returned `io.ErrUnexpectedEOF`. That is not a `*json.SyntaxError`, so the parser logged "skipping malformed record" and continued. `json.Decoder` keeps a read error and returns it from every later `Decode`, while `More()` still sees the unread `{` and returns true, so the loop never ended. It also never checked the context, so the 10-minute job limit did not stop it. `feed_ingest` runs one job at a time, so every feed waited behind it, and the worker log grew to 50 GB of the same warning.

## Decisions and gotchas

- A type error is safe to skip because `Decode` reads the whole value before it unmarshals, so the decoder is already at the next record. The existing tests that skip a string in place of an object still pass.
- A failed page keeps its cursor, so the next job fetches the same page again. Returning the records read so far would advance NVD's `startIndex` by 2,000 and lose the rest of the page.
- Not changed, for Sam: a `*json.SyntaxError` still ends the page and returns the records read so far as a success, and existing tests pin that. For NVD this loses the rest of the page, because the cursor still advances by 2,000. Failing the page instead would make a page that is always corrupt retry forever.
- Not changed: NVD reads the body through `io.LimitReader` at 50 MB, which ends a larger page without an error of its own. With this fix such a page now fails instead of looping, but it would fail on every retry. Measured pages are 6 to 10 MB.
- Not changed: the ingest watcher used for Phase 2 checked only that the worker was alive, so it missed 11 hours with no progress. It now also stops when no watched feed has checkpointed a page for an hour. The watcher is a local script outside the repository.
- gofmt realigned the existing `recordToPatch` struct literal in `internal/feed/kev/adapter.go` when the file was edited.

## Quality checks

- `TestParseNVDResponse/body_that_ends_inside_a_record_returns_an_error`, `TestParseKEV_BodyEndingInsideRecordReturnsError` and `TestFetchPage_BodyEndingInsideRecordReturnsError` each failed on their 5-second deadline before the change, and pass after it.
- `go test ./internal/feed/nvd/ ./internal/feed/kev/ ./internal/feed/ghsa/ -count=1` passes. `golangci-lint run ./internal/feed/...` reports 0 issues. The full suite result is in the pull request.
