# Build a rule's WHERE predicate per candidate list

## What was built

MATCH-2 plan Task 2.2. `CompiledRule.SQL` is replaced by `CompiledRule.Where(candidateIDs []string) sq.Sqlizer` (`internal/alert/dsl/types.go`), because the CVE-set conditions that later tasks add depend on the caller's candidate IDs (design section 5.2). `Compile` now stores one `predicate` closure per SQL condition and the watchlist pre-filter; `Where` combines them by `Logic` exactly as `Compile` combined them before. In this task every predicate ignores the candidate IDs and returns the condition's existing Sqlizer, so the SQL is unchanged.

`internal/alert/evaluator.go` gains `candidateQuery(compiled, candidateIDs)`, which builds the statement `queryCandidates` runs; the later measurement harness reuses it so the measured statement is the production statement. `store.ExecuteDSLQuery` calls `Where(nil)`: saved searches and AI search have no candidate IDs.

## Key decisions

- **Predicates are pure.** The rule cache shares a `CompiledRule` across goroutines, so a predicate only reads values computed in `Compile`, and `Where` builds a new slice on every call.
- **`Where` returns nil for a rule with no SQL conditions and no watchlist.** `Compile` refuses such a rule, but a zero `CompiledRule` reaches `ExecuteDSLQuery` in `TestExecuteDSLQuery_NilSQL`, which keeps its `nil` check.
- **Unknown logic is still refused in `Compile`**, before any predicate is stored, so `Where` only sees `and` or `or`.

## Gotchas

- Before the refactor, a throwaway test captured the candidate statement for six rules (`and` with and without candidates, `or` with a watchlist, a watchlist alone, the FTS join, a regex rule with only a watchlist). `candidateQuery` after the refactor produced the same SQL text and arguments for all six (pointer addresses masked). The throwaway test is not committed.
- No `.SQL` reader remains under `cmd/` or `internal/` (grep).

## Quality checks

- `go test ./internal/alert/dsl/... -count=1`: pass (163 tests), including `TestWhere_IsDeterministicAcrossCalls`.
- `go test ./internal/alert/... -count=1`: pass (300 tests and subtests).
- `go test ./internal/store/... -count=1 -run DSL`: pass (19 tests).
- `go test ./internal/api/... -count=1 -run 'SavedSearch|AI|AlertRule'`: pass (96 tests and subtests).
- `/pitfall-check` on `internal/alert/evaluator.go`, `internal/alert/dsl/*.go` and `internal/store/dsl_executor.go`: no issues.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
