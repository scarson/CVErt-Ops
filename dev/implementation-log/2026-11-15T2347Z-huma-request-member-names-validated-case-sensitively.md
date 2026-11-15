# huma request member names validated case-sensitively

## What was built

| Feature | Files | Description |
|---|---|---|
| Exact name matching in huma validation | `internal/api/openapi_spec.go` (`init`, comment in `newHumaConfig`) | `init` sets `huma.ValidateStrictCasing = true`. huma's validator then matches body member names exactly, as the encoding/json/v2 request format in `newHumaConfig` does, so a case-variant name is a 422 `unexpected property` at its own location. Commit `17d2cc2`. |
| Tests | `internal/api/huma_member_names_test.go`, `internal/api/auth_test.go` | `TestHumaBodyMemberNamesMatchExactly` (no database): a probe operation built with `newHumaConfig` refuses `{"Email":..,"Password":..}` with 422 at `body.Email` and `body.Password` and does not call the handler, refuses a `"PASSWORD"` sibling of a valid `"password"` with 422 at `body.PASSWORD`, and passes exact names to the handler. `TestRegisterCaseVariantMemberRefused`: register with `"Password"` is 422 and creates no user. `TestLoginCaseVariantSiblingRefused`: login with a `"PASSWORD"` sibling is 422 at `body.PASSWORD` with no cookies. |

## Key decisions

- **Defect fixed.** The huma request format added for the v2 migration (`2026-11-15T2313Z-huma-request-bodies-and-clearable-fields-decoded-with-v2.md`) decodes names exactly and ignores unknown ones, while huma's validator, with `ValidateStrictCasing` at its default `false` (`huma@v2.37.3/validate.go:44`, read at :657 for required and property lookup and :707 for `additionalProperties`), matched them case-insensitively. A body with `"Password"` passed `required` and `minLength` and decoded with an empty password; register created such an account.
- **`init`, not `newHumaConfig`.** The setting is a huma package variable read on every request, not part of a config. Setting it in a constructor would hide a process-wide change in a function that looks local. `init` in the file that defines the request format sets it once, before any API is built.
- **Nothing relied on case-insensitive validation.** Only `internal/api` uses huma, and only huma's request validation reads the flag. Tests in `internal/api` that send case-variant names (`channels_test.go`, `contract_test.go`, `scim_*_test.go`, cursor tests) go through `decodeJSON`, SCIM's own decoding or cursor decoding, not huma validation. The `$schema` member is declared with that exact name, so `TestLoginUnknownFieldRefused`'s `$schema` case still passes.

## Gotchas discovered

- `decodeProblem` already exists in `contract_test.go` (it runs `decodeJSON`); the probe test's helper is `probeProblem`.
- A huma operation whose output has no body answers 204, not 200; the probe test asserts 204.

## Quality checks

- Red: `TestHumaBodyMemberNamesMatchExactly` case-variant subtests got 204 (the handler ran); `TestRegisterCaseVariantMemberRefused` got 201 and `TestLoginCaseVariantSiblingRefused` got 200.
- `go test ./internal/api/ -run '^(TestHumaBodyMemberNamesMatchExactly|TestRegisterCaseVariantMemberRefused|TestLoginCaseVariantSiblingRefused)$' -count=1 -v`: pass.
- `go test ./internal/api/ -run 'TestLogin|TestRegister|TestMFA|TestAuth|TestPassword|TestChangePassword|TestResetPassword|TestForgotPassword|TestVerify|TestOpenAPISpec|TestSpec|TestMergeSpecPaths|TestHuma' -count=1 -v`: 109 top-level tests pass, 0 fail; `openapi.json` unchanged.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run.
