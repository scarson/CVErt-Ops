# Fix — OpenAPI Success Statuses for 202 Endpoints

> **Date:** 2026-11-03
> **Commits:** `39cc2a3` on `fix/openapi-async-status` (branched from `dev` at `2dcffc8`); reached `dev` through #147, whose branch was built on it

## What was built

| Feature | Files | Description |
|---|---|---|
| 202 documented | `internal/api/openapi_spec.go` | `DefaultStatus: 202` on admin reindex, feed trigger, ingest, and invitation create; invitation create also documents its `Location` header |
| 201 or 202 | `internal/api/openapi_spec.go` | Alert-rule create documents 201 (rule ready) and 202 (rule activating), both with the rule body and `Location` |
| Status test | `internal/api/openapi_test.go` | `TestOpenAPISpec_SuccessStatusMatchesHandler`; spec building moved into the shared `buildOpenAPISpec` helper |

## Key implementation decisions

- **Second success response declared by hand** — huma derives one response from `DefaultStatus` and the output type. The 202 for alert-rule create is an explicit `Responses["202"]` entry referencing the same `AlertRuleEntry` schema, so both statuses share one component.
- **Explicit `default` error response** — huma adds its generic `default` error response only to operations with a single response and no declared errors, so adding the 202 removed it from alert-rule create. The operation declares it explicitly, matching the other operations' `ErrorModel` response, and the test asserts it on every listed operation.
- **Artifacts not regenerated here** — the production server never serves the spec-only operations; they reach `openapi.json` only through `GENERATE_OPENAPI=1 go test -run TestOpenAPISpec`. Regenerating `openapi.json` and `web/src/lib/api/schema.d.ts` (last done 2026-03-16) and fixing the 201/204 endpoints was done on a separate branch that also reached `dev` through #147.

## Quality checks

- **golangci-lint run ./internal/api/...:** 0 issues
- **Tests:** `internal/api -run TestOpenAPISpec` passes; the new test failed on all five operations before the change.
