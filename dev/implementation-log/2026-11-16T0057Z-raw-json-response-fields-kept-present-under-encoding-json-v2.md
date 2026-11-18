# Raw JSON response fields kept present under encoding/json/v2

## What was built

| Feature | Files | Description |
|---|---|---|
| Raw JSON fields retagged | `internal/api/audit_log.go`, `internal/store/audit.go`, `internal/store/security_events.go` | `auditLogListEntry` and `store.AuditRow` (`old_state`, `new_state`, `metadata`) and `store.SecurityEventRow` (`details`) change from `omitempty` to `omitzero`. A stored `{}` or `null` is written again, as v1 wrote it. Commit `326cc3b`. |
| Wider measurement | `internal/api/response_encoding_test.go` | Each type is encoded in five variants: all nil; empty interfaces holding `""`; RawMessage `{}` with an empty map in interfaces; RawMessage `[]` with an empty slice in interfaces; RawMessage `null`. Struct types that the writeJSON values reach only as slice or map elements (`check.FeedStatus`, `check.ItemResult`, `check.Advisory`, `check.MatchedRange`) are measured on their own. Commit `326cc3b`. |
| gofmt and comment | `internal/api/cves.go`, `internal/api/openapi_spec.go` | Trailing comments in `CVEItem` realigned. The huma format comment now states that the body holds only huma's error text after a failed encoding. Commit `03e8fbb`. |

## Key decisions

- **omitzero for RawMessage.** v2 `omitempty` omits a RawMessage that encodes as `null`, `""`, `{}` or `[]`. v1 omitted it only when it had zero length. `omitzero` omits only nil. A non-nil zero-length value would fail to encode under v2, but no JSONB column produces one. The type comments record this.
- **Request context in the failure log not added.** `writeEncoded` logs without the request context. Adding it would change all 79 `writeJSON` call sites, so the request correlation on this one log line is not kept.
- **Resolved-schema floor kept at 129.** It counts component schemas, which did not change. The element types are added on top, for 145 shapes in total.

## Gotchas discovered

- The first version of the element walk followed unexported fields into `time.Time` and reported `time.zone` as a v2 encoding error. The walk now follows only exported or embedded fields, and it skips types that implement `json.Marshaler` or `encoding.TextMarshaler`.
- A comment placed inside a struct splits gofmt's alignment group and realigns every field. The comments went into the type doc comments instead. gofmt still realigned `SecurityEventRow`, whose tags were already misaligned before this change.

## Quality checks

- Red: `TestResponseEncoding` reported 21 presence entries on the seven fields (`{}`, `[]` and `null` variants).
- Green: expected=362, presence=8 (all on the allowlisted `ErrorModel.status` and `ErrorDetail.value`), error=0, other=0.
- `GENERATE_OPENAPI=1 go test -run '^TestOpenAPISpec$' ./internal/api/`: no content change to `openapi.json`.
- `go test ./internal/api/ -run 'Audit|SecurityEvent|TestResponseEncoding|TestOpenAPISpec' -count=1`: pass (54 top-level tests).
- `go test ./internal/store/ -run 'Audit|SecurityEvent' -count=1`: pass (6 top-level tests).
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/store/...`: 0 issues.
- Full suite not run (the coordinator runs it once per phase).
