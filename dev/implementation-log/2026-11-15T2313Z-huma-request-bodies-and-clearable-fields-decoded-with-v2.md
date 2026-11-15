# huma request bodies and clearable fields decoded with v2

## What was built

| Feature | Files | Description |
|---|---|---|
| huma request format | `internal/api/openapi_spec.go` (`newHumaConfig`) | `cfg.Formats` maps `"application/json"` and `"json"` to a `huma.Format` whose `Unmarshal` is `jsonv2.Unmarshal(data, v)` with v2's defaults and whose `Marshal` is `huma.DefaultJSONFormat.Marshal`. Applies to every huma-registered operation with a body: register, login, refresh, change-password, accept-invitation, forgot/reset-password, verify-email, resend-verification and the MFA operations. Commit `1cb3844`. |
| clearableField value decode | `internal/api/contract.go` (`clearableField[T].UnmarshalJSONFrom`) | Replaces `UnmarshalJSON([]byte)`. Sets `Sent`, reads a `null` token as `Value == nil`, otherwise decodes `T` with `jsonv2.UnmarshalDecode` on the caller's decoder, so `decodeJSON`'s `RejectUnknownMembers` and case-sensitive matching reach inside the field. Commit `16b17f0`. |
| Tests | `internal/api/auth_test.go`, `internal/api/contract_test.go` | `TestLoginMalformedBodyRefused`: duplicate `email` (with `application/json` and with `application/merge-patch+json`) and a password holding the raw byte `0xff` (with `; charset=utf-8`) each give exactly 400, one error at location `body`, no cookies; a valid body gives 200. `TestClearableField_StrictInsideValue`: with a struct `T`, `{"f":{"a":"x","zz":1}}` is 422 at `body.f.zz`, `{"f":{"A":"x"}}` is 422 at `body.f.A`, both with message `unexpected property`; a value, `null` and an omitted key decode as before. |

## Key decisions

- **Two format keys.** huma's `api.Unmarshal` looks the format up by the request media type after removing parameters, or by the part after `+` for a structured-syntax suffix (`parseContentType` in `huma@v2.37.3/api.go`); an unmatched type is a 415. So `"application/json"` and `"json"` are the only keys through which a body is decoded, and replacing both leaves no path to v1. No operation in `internal/api` declares a body `contentType` tag or a `RawBody`.
- **Unknown members stay with huma.** The format does not pass `RejectUnknownMembers`; huma's schema validation already refuses them with a 422 at huma's own location (`TestLoginUnknownFieldRefused`).
- **Request structs holding a clearableField.** `patchWatchlistBody` (`watchlists.go:455`) and `patchSCIMGroupMappingBody` (`scim_admin.go:422`) are both decoded by `decodeJSON`. Their other uses are the spec-only inputs in `openapi_spec.go`, whose handlers never decode a body. The type has no marshal method.

## Gotchas discovered

- huma decodes a body twice: first into `any` for schema validation (`validateBody`), then into the input struct (`parseBodyInto`). A v2 error in the first pass is reported as 400 with `location` `"body"`, as the plan predicted, and the second pass's error is dropped because the body is already invalid.
- On that 400 huma puts the whole request body in `errors[0].value` (`huma@v2.37.3/huma.go`, `validateBody`), so a refused login body echoes the password back to its sender. This was already the case for malformed JSON on v1; the test does not log response bodies.
- The task's `TestSCIMAdmin` test pattern matches no test; the SCIM group-mapping tests that send `mapped_group_id: null` are `TestGroupMapping_*` in `scim_admin_test.go`.

## Quality checks

- Red: before the format change, the duplicate-name login cases returned 200 and the invalid-UTF-8 case 401. Before `UnmarshalJSONFrom`, both refused clearableField cases were accepted by `decodeJSON`.
- `go test ./internal/api/ -run '^TestOpenAPISpec' -count=1`: pass after each task; `openapi.json` unchanged.
- `go test ./internal/api/ -run 'TestLogin|TestRegister|TestMFA|TestAuth|TestPassword|TestInvitation|TestVerify' -count=1 -v`: 70 top-level tests pass, 0 fail.
- `go test ./internal/api/ -run 'TestChangePassword|TestRefresh|TestAcceptInvitation|TestGetInvitation|TestForgotPassword|TestResetPassword|TestResendVerification|TestLogout|TestGetMe' -count=1 -v`: 51 pass, 0 fail.
- `go test ./internal/api/ -run '^(TestSpecOnlyHumaDeclarations|TestSpecMerge|TestMergeSpecPaths)' -count=1`: pass.
- `go test ./internal/api/ -run '^(TestClearableField|TestDecodeJSON)' -count=1 -v`: 8 pass.
- `go test ./internal/api/ -run 'TestWatchlist|TestSCIMAdmin|TestPatch' -count=1 -v`: 56 pass, 0 fail. `go test ./internal/api/ -run '^TestGroupMapping_' -count=1 -v`: 6 pass.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues after each task.
- Full suite not run (the coordinator runs it once per phase).
