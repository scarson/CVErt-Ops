# Saved-search and AI query cursor errors answer 400

## What was built

| Feature | Files | Description |
|---|---|---|
| Cursor error sentinel | `internal/store/dsl_executor.go` (`ErrInvalidCursor`, `decodeDSLCursor`) | `decodeDSLCursor` wraps `store.ErrInvalidCursor` for bad base64 and for JSON that the strict v2 decode refuses. `ExecuteDSLQuery` still prefixes `store: dsl query cursor:`. Commit `f1c873f`. |
| Handler mapping | `internal/api/saved_searches.go` (`executeSavedSearchHandler`), `internal/api/ai.go` (`nlSearchHandler`) | `errors.Is(execErr, store.ErrInvalidCursor)` answers `writeProblem(400, "invalid cursor")`, the problem the other list handlers give for a bad cursor. It is not logged as a server error. Every other `ExecuteDSLQuery` error stays 500 `internal error`. NL search records the request in `ai_request_log` with status `error` and error_type `invalid_cursor`, and counts it in `AIRequestsTotal{status="error"}`, as it does for its other refusals. |
| Tests | `internal/api/saved_searches_test.go`, `internal/api/ai_test.go`, `internal/store/dsl_executor_test.go`, `internal/api/alert_events_test.go` | `TestSavedSearch_ExecuteInvalidCursor` and `TestNLSearchHandler_InvalidCursor`: a cursor in the store's format gives 200; a non-base64 cursor and one with an unknown member each give 400 `invalid cursor` with no `errors` entries. The NL search test also counts two `invalid_cursor` rows in `ai_request_log`. NL search uses `ai.NewMockClient()`, so no Gemini key is needed. `TestExecuteDSLQuery_InvalidBase64Cursor`, `_ValidBase64InvalidJSON` and `_EditedCursor` assert `errors.Is(err, store.ErrInvalidCursor)`. The problem-shape check is the shared helper `assertInvalidCursorProblem`, also used by `TestAlertEvents_EditedCursor`. |
| ABOUTME header | `internal/api/cves_test.go` | The file had none. |

## Key decisions

- **Sentinel in the store, mapping in the handlers.** The store cannot tell a caller's cursor from any other input, so it reports the condition and each handler decides the status. This follows the store's existing `ErrCandidateLimit` pattern.

## Gotchas discovered

- NL search checks the cursor only after the LLM call and the quota increment. A bad cursor on a cache miss therefore still uses one quota unit and one LLM call before the 400. Checking the cursor before the LLM call would need a cursor check exported from the store. Not changed here.
- `doExecuteSavedSearch` appends `/execute` after the ID, so a query string cannot be passed through its `id` argument. The new test builds its own request.
- The repository's formatter hook reorders imports and realigns tables in `ai_test.go` and reflows one-line structs in `alert_events_test.go` on every edit. Those changes were reverted so the commit holds only the intended lines.

## Quality checks

- Red: before the change, both handlers answered 500 `internal error` for the malformed and edited cursors, and the store errors did not match `ErrInvalidCursor`.
- `go test ./internal/api/ -run 'Cursor|TestSavedSearch|TestAI|TestNLSearch' -count=1 -v`: 59 top-level tests pass, 0 fail.
- `go test ./internal/store/ -run 'DSLCursor|ExecuteDSL' -count=1 -v`: 21 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/store/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
