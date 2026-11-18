# Response encoding measurement covers collection elements

## What was built

| Feature | Files | Description |
|---|---|---|
| Element variants | `internal/api/response_encoding_test.go` | `TestResponseEncoding` builds every type in ten variants. There are five raw-JSON and interface fills, and each runs once with nil slices and maps and once with one element in every slice and one zero-key entry in every map. Elements are filled the same way, nested up to the depth bound. This replaces the separate walk that measured element struct types on their own. Commit `ba535b3`. |
| Nullable guard | same file (`omitzeroNullablePointers`, `isPlainStruct`, `TestIsPlainStruct`) | A pointer tagged `omitzero` must carry `nullable:"false"` unless its element is a plain struct, meaning a struct that is not `time.Time`, not `url.URL`, and has no `UnmarshalText`. |
| Map literals by handler | same file (`writeJSONResponseValues`, `TestWriteJSONMapLiteralsListed`) | Entries are labelled by handler name. A go/ast check fails for any handler that passes `writeJSON` a map literal, or a variable assigned from one in the same function, without an entry. |

## Key decisions

- **Nullability of collections in the spec.** huma's `DefaultArrayNullable` is true, so response arrays appear in `openapi.json` as `["array","null"]` and in `schema.d.ts` as `T[] | null`. Maps appear as `type: object` and are not nullable. The phase leaves the spec unchanged. What it gains is consistent output: v2 writes `[]` and `{}` for nil slices and maps, so a nil map now matches its schema. Commit `1ff8098`'s message says that both arrays and maps match the published schemas; that holds for maps only.
- **Nested ErrorDetail.value allowlisted.** `ErrorModel.errors[].value` has the same cause as `ErrorDetail.value`: v1 echoes `""`, `[]` or `{}`, and v2 drops it. Allowlist keys write array indexes as `[]`.

## Gotchas discovered

- The AST check sees only maps whose literal is in the same function as the `writeJSON` call. A map built in a helper and passed through a variable would not be caught.

## Quality checks

- `go test ./internal/api/ -run 'TestResponseEncoding|TestIsPlainStruct|TestWriteJSONMapLiteralsListed|TestOpenAPISpec' -count=1`: pass. The measurement reports 155 shapes and expected=337, presence=19, error=0, other=0. All 19 presence entries are on allowlisted huma fields.
- Break test: after renaming two handler entries, `TestWriteJSONMapLiteralsListed` failed for both (one inline literal, one variable).
- `golangci-lint run --allow-parallel-runners ./internal/api/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
