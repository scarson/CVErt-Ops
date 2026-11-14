# Concurrency test for CompiledRule.Where, and harness rows within the new limit

## What was built

| Feature | Files | Description |
|---|---|---|
| Concurrency test | `internal/alert/dsl/where_concurrency_test.go` | 32 goroutines call `Where` 50 times each on one compiled rule (products, ecosystems, packages, severity, a watchlist), under `and` and `or`, with no, one and three candidate IDs; every result equals the serial one. Passes under `go test -race`. |
| Harness | `internal/alert/kept_ingest_measure_test.go` | The limit rule under `and` and the 20- and 50-set `and` sweep rows are removed: an `and` rule may now hold at most 10 set conditions, and Validate refuses more. Their earlier numbers stay in the measurements file. |
| Message style | `internal/merge/pipeline.go` | The rename re-check error uses the arrow the file's other messages use. |

## Gotchas discovered

- **`pq.Array` returns a new pointer on every call**, so comparing compiled arguments with `%#v` reports a difference every time. Compare the arguments' `driver.Valuer` values instead.

## Quality checks

- `go test ./internal/alert/dsl/ -run TestWhere_ConcurrentCallsMatchSerialResult`, with and without `-race`: pass.
- `go test ./internal/merge/...` filtered to the late-binding and rename tests: pass.
- golangci-lint v2.15.0 on `./internal/alert/...`, `./internal/merge/...`, and the harness with `--build-tags keptingest`: 0 issues.
