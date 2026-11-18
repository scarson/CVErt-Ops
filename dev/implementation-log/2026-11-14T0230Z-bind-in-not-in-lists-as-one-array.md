# Bind in and not_in lists as one array parameter

## What was built

MATCH-2 plan Task 2.1. The alert DSL's `setSQL` (`internal/alert/dsl/compiler.go`) compiles `in` to `<expr> = ANY(?)` and `not_in` to `<expr> <> ALL(?)` with the list bound as one `pq.Array` parameter, for every string and enum field (`cve_id`, `severity` and the other set fields). Squirrel's `sq.Eq`/`sq.NotEq` rendered one placeholder per value, so one `cve_id in [...]` condition could pass PostgreSQL's 65,535-parameter limit inside the 1 MiB request limit (pitfall DB-12).

## Key decisions

- **A nil list binds an empty array.** The validator accepts JSON `null` for a list, which unmarshals to a nil slice, and `pq.Array(nil)` binds SQL NULL. `<> ALL(NULL)` is NULL, so `not_in: null` would have matched nothing instead of everything. With `[]string{}` the results are those squirrel gave: an empty `= ANY` is false (squirrel's `(1=0)`) and an empty `<> ALL` is true (squirrel's `(1=1)`). NULL columns behave as before: `NULL <> ALL(arr)` is NULL, as `NULL NOT IN (...)` was.

## Gotchas

- `TestCompile_EnumIn` also asserted the old placeholder count; it was updated with `TestCompile_EnumNotIn` and `TestCompile_StringNotIn`, which the plan names.

## Quality checks

- `go test ./internal/alert/dsl/... -count=1`: pass (162 tests), including `TestCompile_SetListIsOneParameter` (70,000 IDs give one placeholder and one argument) and `TestCompile_NullListBindsEmptyArray`.
- `go test ./internal/store/... -count=1 -run DSL`: pass (19 tests). `TestExecuteDSLQuery_EmptySeverityLists` runs on a `SeedCorpus` database: `severity not_in null` and `not_in []` return all 62 visible CVEs, 27 of them with NULL severity; `in null` and `in []` return none. With the nil normalisation removed, the `not_in null` case fails (0 of 62).
- `go test ./internal/alert/... -count=1 -run Evaluator`: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
