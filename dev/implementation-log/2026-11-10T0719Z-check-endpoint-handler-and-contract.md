# Check endpoint handler and API contract

## What was built

- Task 3.10 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `6e8f968`.
- `internal/api/check.go`: `checkComponentsHandler` for `POST /api/v1/orgs/{org_id}/check`, routed in `server.go` with `RequireOrgRole(RoleViewer)`. Order: take a check slot or answer 503 with `Retry-After: 1`; `io.ReadAll` the body, answering 413 when `errors.As` finds `*http.MaxBytesError`; put the bytes back as `r.Body` and `decodeJSON` (400 on malformed JSON); 422 when `items` is missing, null, empty or over `maxCheckItems` (500); `check.ParseItem` for each item; `check.KeysFor`; a 30-second context; `store.ReadCheckCandidates`; `check.EvaluateWithLimits` with `check.FeedStatuses(rows, time.Now())` and `srv.checkLimits`; `writeJSON` of `check.Results`.
- `writeCheckFailure` answers a failed read or evaluation: `store.ErrCandidateLimit` is 422 with problem type `urn:cvert:error:candidate_limit_exceeded`; an ended check context is 503 with no partial answer, whatever error the driver returned; anything else is logged and 500.
- `Server` gains `checkSem` (capacity `maxConcurrentChecks = 4`) and `checkLimits` (`check.DefaultLimits`), both set in `NewServer`. `acquireCheck` and `releaseCheck` follow `acquireArgon2`: no waiting, release by `defer`.
- Spec: `registerCheckSpecOps` (operation `check-components`, default status 200, tag `Version Check`) in `registerAllSpecOps`; `"POST /orgs/{org_id}/check": roleOp("viewer")` in `operationAccess`. Named body types `CheckRequest`, `CheckItem`, `CheckResults`, `CheckItemResult`, `CheckAdvisory`, `CheckMatchedRange`, `CheckComponent`, `CheckCounts`, `CheckItemError`, `CheckFeedStatus`, with design section 11's enumerations as `enum` tags and the plan's descriptions. `openapi.json` and `web/src/lib/api/schema.d.ts` regenerated.

## Decisions and gotchas

- One source of truth for the response: the handler writes `check.Results`; the `Check*` response types exist only for the spec. `TestCheckResponseTypesMatchResults` fills every field of one type tree by reflection (and builds a sparse value with nil pointers and empty strings), marshals it, decodes it into the other tree and requires the same JSON, in both directions. A field added, dropped or made nullable on one side fails it.
- The handler decodes into `CheckRequest` and converts each `CheckItem` with `check.RawItem(raw)`. The conversion compiles only while the two structs have the same fields, so the request shape cannot drift either.
- `component` and `error` are null for some items, and huma refuses `nullable` on a `$ref` field. A blank `_ struct{} \`nullable:"true"\`` field on `CheckComponent` and `CheckItemError` makes those schemas `["object","null"]`, so the generated TypeScript reads `CheckComponent | null`. Both types appear only in those nullable positions. Nullable enums (`reason`, `fix_major`) come out as `... | null` without help.
- Field length limits are in the item descriptions, not `maxLength` tags: an over-long field gives that item `value_too_long` with a 200, not a 422, so `maxLength` would misdescribe the server.
- `ErrCandidateLimit` is not reachable through the handler without 200,000 stored rows or a store hook, and the store's limits are unexported. `TestWriteCheckFailure` tests the error mapping directly (wrapped `ErrCandidateLimit`, also after the context ended; `context.Canceled`; a driver error after cancellation; a passed deadline; any other error, which alone is logged). The store tests already show `ReadCheckCandidates` returns it.
- A cancelled context is tested by calling the handler directly with a cancelled request context holding the org ID, because a client that cancels never sees the response. The store read fails and the answer is 503.
- `securityFixture` (in `openapi_security_test.go`) now also holds the `*Server` and the `TestDB`, so the check tests reuse it instead of copying its org, enterprise tier and per-role API keys.
- The commit could not be made with the pathspec form alone: `git commit -- <paths>` refuses untracked files. The two new files were added by name first.

## Quality checks

- Tests written first; they failed to build, then ran against a stub handler answering 501: every handler test and `TestWriteCheckFailure` failed, and `TestOpenAPISpec` failed on the stale `openapi.json`.
- Verify-first from the plan (the 413 path): with the `errors.As` branch removed, the 1 MiB-plus body got 400 ("could not read the request body") and `TestCheckAPI_RequestErrors` failed; branch restored.
- Break tests, run once and reverted: logging the request's keys fails `TestCheckAPI_DoesNotLogItems`; removing `omitempty` from `CheckMatchedRange.fixed` fails `TestCheckResponseTypesMatchResults` in both directions.
- `go test ./internal/api/ -run 'Check|OpenAPI' -count=1 -v`: pass, 28 top-level tests and 73 subtests, including `TestOpenAPISecurity_MatchesEnforcement` (no body gives 400 to a viewer key), `TestOpenAPISecurity_TableCoversEveryOperation`, `TestOpenAPISpec_SchemaNamesFitGeneratedClients` and `TestOpenAPISpec_CheckItemsCapMatchesHandler`.
- `golangci-lint run ./internal/api/...`: 0 issues. `cd web && npm run type-check`: pass.
