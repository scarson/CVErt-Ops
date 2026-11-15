# Pagination cursors decoded with strict v2 options

## What was built

| Feature | Files | Description |
|---|---|---|
| Strict cursor decode | `internal/api/contract.go` (`decodePageCursor`), `internal/api/cves.go` (`decodeCursor`), `internal/store/dsl_executor.go` (`decodeDSLCursor`) | Each decodes the base64-decoded cursor JSON with `jsonv2.Unmarshal(raw, dst, jsonv2.RejectUnknownMembers(true))`. A member the cursor type does not define, a member name in another case, a duplicate member or trailing data makes the cursor invalid. The encoders stay on v1 `json.Marshal`. Commit `02867f3`. |
| Tests | `internal/api/contract_test.go`, `internal/api/cves_test.go`, `internal/api/alert_events_test.go`, `internal/store/dsl_executor_test.go` | `TestDecodePageCursor_RefusesEditedCursor` and `TestDecodeCursor_RefusesEditedCursor`: unknown member, case variant and duplicate name each refused (plus trailing value and a case variant in the padded encoding for `decodePageCursor`). `TestPageCursorTypes_RoundTrip`: all 13 cursor types passed to `encodePageCursor` round-trip through the v1 encoder and the v2 decoder; `TestPageCursor_TimeWithOffsetRoundTrip` does the same for a `time.Time` with a non-UTC offset. `TestAlertEvents_EditedCursor`: through `GET /orgs/{org_id}/alert-events`, the unedited cursor gives 200 and each edited cursor gives 400 with detail `invalid cursor` and no `errors` entries, the response a malformed cursor already got. `TestExecuteDSLQuery_EditedCursor`: the three edits through `ExecuteDSLQuery` return a `dsl query cursor` error. |

## Key decisions

- **Cursor field types checked before the switch.** Every cursor struct holds only `string`, `int`, `int64` and `time.Time` fields with lowercase tags that the v1 encoder writes exactly; none has a `,string` tag, `time.Duration`, `[]byte`, map or interface. v2 decodes the RFC 3339 text that v1 writes for `time.Time`.
- **No other cursor decoder.** The plan's grep for `base64.(Raw)URLEncoding.DecodeString` outside tests finds only the three decoders; the remaining base64 decode in production code is `internal/auth/hash.go` (argon2id salt and key, not JSON). `evalCursor` in `internal/alert/evaluator.go` is a stored worker cursor, not caller input, and stays on v1 under the stored-read policy.
- **Handler response unchanged.** List handlers already map a `decodePageCursor` error to `writeProblem(400, "invalid cursor")`; an edited cursor now takes that same path.

## Gotchas discovered

- `TestExecuteDSLQuery_CraftedCursor` built its cursor with key `"s"`, but `dslCursor` defines `d` and `c`. v1 ignored `"s"`, so the cursor had a zero date and `ExecuteDSLQuery` skipped the keyset WHERE: the test passed without exercising the crafted date. It now uses `"d"` with an RFC 3339 time. Because a far-future date returns every row with or without the WHERE, the test also sends a cursor dated between the newest and second-newest seeded CVE and checks that only the two older CVEs return.
- The saved-search execute and AI query handlers map every `ExecuteDSLQuery` error, a bad cursor included, to 500 `internal error` (`saved_searches.go:457-461`, `ai.go:199-206`). This predates the change; an edited cursor there now gets the same 500 a malformed one already got.
- The repository's Go formatter hook reflowed one-line anonymous structs in `alert_events_test.go`; those lines were restored so the commit holds only the test addition.

## Quality checks

- Red: before the decoder change, the edited-cursor unit cases were accepted, `TestAlertEvents_EditedCursor`'s three edited cursors returned 200, and `TestExecuteDSLQuery_EditedCursor`'s three cursors returned results without error.
- `go test ./internal/api/ -run 'Cursor' -count=1 -v`: 21 top-level tests pass, 0 fail.
- `go test ./internal/api/ -run 'Pagination|AlertEvents_Feed|AdminSystem|AdminAudit' -count=1 -v`: 13 pass, 0 fail (handlers that reissue their own cursors).
- `go test ./internal/store/ -run 'DSLCursor|ExecuteDSL' -count=1 -v`: 21 top-level tests pass, 0 fail.
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/store/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
