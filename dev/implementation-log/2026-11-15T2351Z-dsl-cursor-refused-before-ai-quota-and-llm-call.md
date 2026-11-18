# DSL cursor refused before the AI quota and LLM call

## What was built

| Feature | Files | Description |
|---|---|---|
| Cursor check | `internal/store/dsl_executor.go` (`ValidateDSLCursor`) | Returns `decodeDSLCursor`'s error: nil for an empty cursor, an error wrapping `ErrInvalidCursor` for any cursor `ExecuteDSLQuery` would refuse. Commit `9e6309a`. |
| Early refusal | `internal/api/ai.go` (`nlSearchHandler`), `internal/api/saved_searches.go` (`executeSavedSearchHandler`) | Each handler calls `store.ValidateDSLCursor` as soon as it reads `?cursor=` and answers `writeProblem(400, "invalid cursor")`. NL search does this before the cache lookup, quota increment and LLM call; saved-search execute does it after the saved-search lookup and access check, before the DSL work. Like the handlers' other early caller errors, this writes no `ai_request_log` row and increments no metric. The `errors.Is(execErr, store.ErrInvalidCursor)` branches after `ExecuteDSLQuery` stay as a commented backstop and only write the 400. |
| Tests | `internal/api/ai_test.go`, `internal/store/dsl_executor_test.go`, `internal/store/export_test.go` | `TestNLSearchHandler_InvalidCursor` uses a test-local `countingLLM`, which embeds `*ai.MockClient` and counts `GenerateStructuredQuery` calls. Every request uses its own query, so each one is a cache miss. A valid cursor first shows that a cache miss can be observed (quota 1, 1 log row, 1 LLM call). The malformed and edited cursors then leave the org's `ai_usage_counters` count, its `ai_request_log` rows, the LLM call count and `AIRequestsTotal{nl_search,error}` unchanged. `TestValidateDSLCursor` needs no database: empty and store-issued cursors (via the test-only `store.EncodeDSLCursor`) pass; non-base64, non-JSON, unknown-member, case-variant and duplicate-name cursors return `ErrInvalidCursor`. |

## Key decisions

- **Validate, then decode again.** `ExecuteDSLQuery` keeps its own decode, so its signature is unchanged and a direct caller is still checked. Decoding twice costs one small base64 and JSON decode per request.

## Gotchas discovered

- `ai.MockClient` has no call counter. The test wraps it instead of changing the shared mock.

## Quality checks

- Red: with `ValidateDSLCursor` stubbed to return nil, the invalid cursors raised the quota count from 1 to 3 and the log rows from 1 to 3, made 2 LLM calls, and the invalid `TestValidateDSLCursor` cases failed.
- `go test ./internal/api/ -run 'Cursor|TestNLSearch|TestSavedSearch|TestAI' -count=1 -v`: 59 top-level tests pass, 0 fail.
- `go test ./internal/store/ -run 'DSLCursor|ExecuteDSL|ValidateDSLCursor' -count=1 -v`: 22 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/store/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
