# SCIM request bodies decoded with strict v2 options

## What was built

| Feature | Files | Description |
|---|---|---|
| Shared SCIM body decoder | `internal/api/scim_types.go` (`scimJSONOptions`, `decodeSCIMBody`) | `jsonv2.UnmarshalRead(r.Body, dst, scimJSONOptions)` with `jsonv2.MatchCaseInsensitiveNames(true)` and v1's `json.MatchCaseSensitiveDelimiter(true)`, without `RejectUnknownMembers`. On error it writes `writeSCIMError(w, 400, scimType, "invalid JSON body")` and returns false. |
| Six callers | `internal/api/scim_users.go` (create, replace, PATCH user), `internal/api/scim_groups_handler.go` (create, replace, PATCH group) | Each `json.NewDecoder(r.Body).Decode` block calls `decodeSCIMBody`; users pass scimType `""`, groups pass `"invalidValue"`, as before. The scalar PATCH `value` decoders, `extractMemberValues` and the pathless-replace map decode are unchanged. |
| Tests | `internal/api/scim_types_test.go`, `internal/api/scim_users_test.go`, `internal/api/scim_groups_handler_test.go` | `TestDecodeSCIMBody_Refused` (case-variant and exact duplicate, trailing value, invalid UTF-8, empty, malformed; each with both scimTypes, asserting status, scimType and detail), `TestDecodeSCIMBody_Accepted` (case-insensitive name, `user_name`/`external_id` and `user-name`/`external-id` not folded, enterprise extension ignored), `TestDecodeSCIMBody_OversizedBody`, `TestSCIMCreateUser_DuplicateAttributeRefused` (no user by externalId or either email afterwards), `TestSCIMPatchGroup_DuplicateAttributeRefused` (`value` and `VALUE` in one operation; displayName unchanged in the store). Helpers `sendSCIMRawBody` and `decodeSCIMErrorResponse` in `scim_users_test.go`. |

## Key decisions

- **Body size limit.** No SCIM handler sets its own limit; the global `middleware.RequestSize(1 << 20)` in `server.go` covers the SCIM sub-router, and chi implements it as `r.Body = http.MaxBytesReader(w, r.Body, n)`. `UnmarshalRead` reads to EOF, so it sees `*http.MaxBytesError` once the limit is passed and returns an error; `TestDecodeSCIMBody_OversizedBody` wraps the body in `http.MaxBytesReader` the same way and gets the 400. A body whose first value fits under the limit but whose trailing bytes pass it is now refused; v1's `Decode` stopped after the first value.
- **Group PATCH test uses a duplicate inside the operation object.** `{"op":"replace","path":"displayName","value":"A","VALUE":"B"}` duplicates a member of `SCIMPatchOperation`, which the outer decode checks. Case-variant duplicates inside a `value` (member lists, the pathless-replace map) are not checked by the outer decode and are Task 2.2's work.

## Gotchas discovered

- `go doc encoding/json MatchCaseSensitiveDelimiter` confirms it is a v1-package `Options` that v2 calls accept (go1.27.4); `go doc encoding/json/v2 MatchCaseInsensitiveNames` confirms that case variants of one field count as duplicate names.
- `noctx` flags `httptest.NewRequest`; the unit tests use `httptest.NewRequestWithContext`.

## Quality checks

- Red: before the decoder existed, `TestDecodeSCIMBody*` did not compile. With `decodeSCIMBody` added but the handlers still on v1, `TestSCIMCreateUser_DuplicateAttributeRefused` got 201 (user provisioned as `dup-attr-b@example.com`) and `TestSCIMPatchGroup_DuplicateAttributeRefused` got 200.
- `go test ./internal/api/ -run 'TestSCIM|TestDecodeSCIMBody|TestScim' -count=1 -v`: 81 top-level tests pass (105 including subtests), 0 fail, 0 skip.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
