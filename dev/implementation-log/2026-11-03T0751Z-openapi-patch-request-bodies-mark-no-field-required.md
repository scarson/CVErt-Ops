# OpenAPI — PATCH Request Bodies Mark No Field Required

> **Date:** 2026-11-03
> **Branch:** `fix/patch-bodies-optional`

## What was built

| Part | Files | Description |
|---|---|---|
| PATCH DTO tags | `internal/api/alert_rules.go`, `channels.go`, `reports.go`, `sso.go`, `watchlists.go` | Every field of `patchAlertRuleBody`, `patchChannelBody`, `patchReportBody`, `patchSSOBody` and `patchWatchlistBody` has `,omitempty` in its `json` tag, as the SCIM PATCH bodies already had |
| Spec test | `internal/api/openapi_test.go` | `TestOpenAPISpec_PatchBodiesOptional` covers all seven PATCH body schemas |
| Watchlist rename | `web/src/views/WatchlistDetailView.vue` | The PATCH body carries only the changed fields instead of `null` for the unchanged ones |

## Key implementation decisions

- **`omitempty` only changes the spec here.** huma marks a field required when its `json` tag has no `omitempty`. These structs are only decoded (`decodeJSON`) and used as spec-only request bodies, never encoded, so the tag does not change runtime behavior.
- **The fields are no longer nullable in the spec.** huma marks a pointer field nullable only when it is required, so the generated TypeScript types changed from `string | null` (required) to `string` (optional). A JSON `null` still decodes to a nil pointer, which the handlers treat as omitted.
- **Response DTOs needed no nullability change.** Pointer fields without `omitempty` (for example `ScimGroupItem.external_id`) are already `["string", "null"]`, slices are nullable by default in huma 2.37, `json.RawMessage` gets the any (`{}`) schema, and the one map field (`TierResponse.limits`) is never nil.

## Gotchas discovered

- **`patchWatchlistBody.GroupID **string` cannot tell `null` from omission.** `encoding/json` sets the outer pointer to nil for a JSON `null`, so `{"group_id": null}` keeps the current group instead of clearing it, contrary to the struct's doc comment. Not fixed here. Before this change the SPA sent `group_id: null` on every rename, which would have cleared the group if the decoding had worked as documented.

## Quality checks

- **Spec test:** failed for the five schemas before the tag change; passes after.
- **Go:** `go test ./internal/api/ -run '(?i)patch|OpenAPISpec'` passes; golangci-lint: 0 issues on `internal/api`.
- **Frontend:** `generate-api`, `type-check` and `lint` clean; `WatchlistDetailView.test.ts` 21/21, including a new assertion on the PATCH body that failed before the view change.
