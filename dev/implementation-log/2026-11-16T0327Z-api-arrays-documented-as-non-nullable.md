# API arrays documented as non-nullable

## What was built

| Feature | Files | Description |
|---|---|---|
| Non-nullable arrays in the spec | `internal/api/openapi_spec.go`, `openapi.json`, `web/src/lib/api/schema.d.ts` | The api package `init` sets `huma.DefaultArrayNullable = false` next to `huma.ValidateStrictCasing`. 82 schemas change from `["array","null"]` to `"array"`: 70 response-only, 11 request-body fields, and the `GET /cves` query-parameter array. Commit `ad6fd04`. |
| SSO create scopes optional | `internal/api/sso.go` | `createSSOBody.Scopes` has `omitempty` and a doc saying that omitting it requests openid, profile and email. Before, the spec marked it required, so once it was non-nullable the spec gave no way to request the defaults. |
| Spec and behavior tests | `internal/api/openapi_test.go`, `internal/api/sso_test.go` | `TestOpenAPISpec_ArraysNotNullable` walks the whole spec. It reported 82 failures with the flag commented out. `TestOpenAPISpec_SSOCreateScopesOptional` failed before the `omitempty` change. `TestSSOConnection_CreateWithoutScopesUsesDefaults` pins the existing store default, and it passes with or without the change. |
| SPA guard cleanup | 11 files under `web/src/views` and `web/src/components` | Removed `?? []` on `items` in list responses and on feed `recent_logs`, where the response object is already narrowed. In two feed views, an identity `.map` became plain assignment. CveDetailView tests mock empty arrays as `[]`. Commit `e609fb0`. |

## Key decisions

- **No change to how requests are handled.** The 11 request-body fields are `CheckRequest.items`, `CreateAlertRuleBody`/`ValidateRuleBody`/`CreateReportBody.watchlist_ids`, `CreateSSOBody`/`PatchSSOBody.scopes`, `PutSSODomainsBody.domains`, `IngestRequest.patches`, `IngestPatch.references`, `IngestRef.tags` and `ReplaceWatchlistItemsBody.items`. All of them are on chi routes that are declared only for the spec, and `decodeJSON` decodes them. Huma does not validate them, so the server still accepts `null`. No huma-native operation has an array in its request body. A future one would reject `null`.
- **Where null has a meaning:** `CreateSSOBody.scopes` (null means the default scopes; now documented as "omit"), `CreateReportBody.watchlist_ids` (null means all watchlists, and the handler treats `[]` the same) and `PatchSSOBody.scopes` (null or omitted means no change; the field was already optional). The SPA sends none of the 11 bodies.
- **Guards kept:** `data?.x ?? []` where `data` can be undefined, and the guards on CveDetailView's `affected_packages`, `affected_cpes` and `references`, which are optional (`?:`) in the generated types.
- **SCIM protocol routes not affected.** `/scim/v2` routes still write with the v1 encoder (`writeSCIMJSON`), but they are not in `openapi.json`.

## Gotchas discovered

- A fresh worktree cannot build `internal/api` until `web/dist` exists (`web/embed.go` embeds `all:dist`). Run `npm ci && npm run build` in `web` first.

## Quality checks

- `go test -run 'TestOpenAPI|TestSSOConnection' ./internal/api/ -count=1`: pass.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- `npm run type-check`: clean. Before the guard and mock changes, it reported 3 errors, all in `CveDetailView.test.ts` null mocks. `npm run lint`: 0 warnings, and `--fix` changed nothing. `npm run test:unit -- --run`: 540 of 540 pass.
