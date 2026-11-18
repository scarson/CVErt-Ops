# API responses encoded with encoding/json/v2

## What was built

| Feature | Files | Description |
|---|---|---|
| Response encoding measurement | `internal/api/response_encoding_test.go` | `TestResponseEncoding` collects every component schema reachable from a response in the production and spec-only OpenAPI registries (129, all resolved through `TypeFromRef`) plus the `writeJSON`, readyz and healthz values no schema covers. It encodes each one with v1 and with `responseJSONOptions`, in two versions: one with pointers to zero values and nil collections, and one that also sets every empty interface to `""`. It fails on any difference except a nil slice or map becoming `[]` or `{}`. It also fails when a response pointer-to-scalar field is tagged `omitzero` without `nullable:"false"`. Commit `250c0ba`. |
| Field presence kept | `cves.go`, `alert_events.go`, `audit_log.go`, `deliveries.go`, `orgs.go`, `reports.go`, `saved_searches.go`, `watchlists.go` | 45 response `*string` fields go from `omitempty` to `omitzero nullable:"false"`, so a pointer to `""` is still written as `""`. Commit `250c0ba`. |
| chi response writers | `internal/api/contract.go` (`writeEncoded`, `responseJSONOptions`), `readyz.go`, `server.go` | `writeJSON`, the three problem writers, readyz and healthz encode with v2 (Deterministic, AllowInvalidUTF8) before setting headers. An encoding failure is logged and answered with a fixed 500 problem body. Commit `1ff8098`. |
| huma response format | `internal/api/openapi_spec.go` (`newHumaConfig`) | The JSON format marshals with the same options, encodes in full before writing, and keeps the trailing newline. Commit `df93bf0`. |

## Key decisions

- **`nullable:"false"` alongside `omitzero`.** huma clears the nullable flag of a scalar pointer only when its json tag contains `omitempty` (huma@v2.37.3 `schema.go:927-931`). With `omitzero` alone, all 53 property schemas became `"type": ["string","null"]` in `openapi.json`. v2 never writes `null` for an `omitzero` pointer, so the tag is accurate, and `openapi.json` and `schema.d.ts` stay unchanged.
- **Allowlisted huma fields.** `ErrorModel.status`: v2 writes `0` where v1 omits it, and every writer sets a non-zero status. `ErrorDetail.value`: when the value is `""`, v2 omits it, and an empty echoed value carries no information.
- **Fixed fallback body.** The 500 problem body for an encoding failure is a constant, so writing it cannot fail.

## Gotchas discovered

- Measurement before the retag, counted as unique paths: 69 *expected* (nil slice or map), 55 *presence*, 0 *error*, 0 *other*. The measurement works per type: several *expected* paths cannot be nil in production (`writeList` items, `doctor.Run`, ingest errors).
- huma's `transformAndWrite` (huma.go:601-637) calls `SetStatus`, and humachi writes the header at once, before it calls `Marshal`. If a huma response fails to encode, the client still gets the operation's status and huma's text "error marshaling response". The format now writes no partial JSON before that text, but the status is still wrong. The status cannot be fixed inside the format.
- gosec G705 (XSS via taint) on the response write is a false positive. The body is JSON served with a JSON media type and `X-Content-Type-Options: nosniff`. It is suppressed inline with that reason.

## Quality checks

- 6.1 red: `TestResponseEncoding` failed with 109 presence entries. Green after the retag.
- 6.3 red: `TestWriteJSON_NilSliceIsEmptyArray` (body `{"tags":null}`) and `TestWriteJSON_MarshalFailureWritesProblem` (status 200) failed. Green after the change.
- 6.4 red: `TestHumaResponseFormat` failed (`tags`/`labels` were null). Green after the change.
- `go test ./internal/api/ -count=1`: pass (1063 top-level tests) after 6.3 and again after 6.4.
- `GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/`: no content change to `openapi.json`. `npm run generate-api`: no change to `schema.d.ts`.
- SPA: no null comparison or truthiness check on a response collection depends on `null`. Existing checks use `.length` or `?? []`. `npm run type-check`, `npm run lint` and `npm run test:unit -- --run` (540 tests) pass, with no changes.
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
