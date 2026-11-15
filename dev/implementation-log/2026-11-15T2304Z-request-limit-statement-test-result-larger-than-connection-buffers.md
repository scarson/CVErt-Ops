# Request-limit statement test result larger than the connection buffers

## What was built

| Feature | Files | Description |
|---|---|---|
| Padded ranges | `internal/store/check_test.go` (`TestReadCheckCandidates_RequestLimitStopsStatement`) | Each of the 3000 ingested ranges has a fixed version padded with 1000 characters, so the packages statement returns about 3.3 MB instead of about 270 KB. The doc comment says why the size matters. |

## Key decisions

- **Grow the result, not the row count.** Padding the existing 3000 ranges keeps ingest at about 0.8 s; the test still runs in about 0.9 s. The scan-error sibling already reads 100000 `generate_series` rows (about 1.5 MB, estimated from the row encoding, not measured) for the same reason.
- **No production change.** `readKeyRows` cancels the statement's context before closing its rows. Reading data the client already holds is bounded by the buffer sizes, and a statement larger than them is stopped, which is what the cancel is for.

## Gotchas discovered

- pgx v5 reacts to a cancelled context through `context.AfterFunc`: another goroutine sets the connection's read deadline (`DeadlineContextWatcherHandler`). Until it runs, `Rows.Close` keeps reading whatever is in pgx's read buffer and the socket buffers. A result that fits there can be read to its `CommandComplete`, and the tracer then reports a command tag with no error.
- A diagnostic (read two rows, wait, cancel, close) on the 270 KB result: with GOMAXPROCS=1 and a 10 ms or 100 ms wait, 1/10 and 2/10 tries completed; with more procs, 0/40. The 3.3 MB result completed in 0/80 tries under every setting. The full-suite failure took 11.98 s against about 0.9 s alone, which matches CPU starvation of the deadline goroutine.
- The test comment's "more rows than pgx buffers" was the wrong bound: pgx's own buffer is small, but the OS socket buffers on the path also hold rows.

## Quality checks

- Break-test: without the `defer cancel()` that runs before the deferred `rows.Close`, the test fails 3/3 with `SELECT 3000`. Reverted.
- `go test ./internal/store/ -run 'TestReadCheckCandidates_RequestLimitStopsStatement$' -count=20`: 20 pass, 0.80-1.25 s each after the first (3.26 s, container start).
- `go test ./internal/store/ -run 'TestReadCheckCandidates' -cpu=1 -count=5`: pass (115 test results).
- `go test ./internal/store/ -run 'TestReadCheckCandidates_(RequestLimit|ScanError)StopsStatement$' -cpu=1,4 -count=20` with every CPU saturated by busy-loop processes: 80 pass.
- `go test ./internal/store/ -count=1`: pass (33 s).
- `golangci-lint run --allow-parallel-runners ./internal/store/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
