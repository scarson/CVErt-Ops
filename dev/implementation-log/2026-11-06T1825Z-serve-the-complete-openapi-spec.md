# Serve the complete OpenAPI spec

## What was built

- `/api/v1/openapi.json` and `/api/v1/openapi-3.0.json` describe every API route: 104 paths, up from 25. `Handler` merges the spec-only declarations for chi-backed routes.
- `servers: [{url: "/api/v1"}]`, so clients and the documentation page find the API under its mount point.
- `TestOpenAPISpec_MatchesRoutes` walks the chi router and fails on a route with no spec entry or a spec entry with no route.
- `TestOpenAPISpec` compares the served spec with the committed `openapi.json`, and the web CI job regenerates `schema.d.ts` and fails on a diff.

## Key decisions

- One `newHumaConfig` for the production and spec-only APIs. Huma builds `ErrorModel`'s `$schema` example from the server URL, so setting `servers` on the production API alone makes `mergeSpecPaths` panic with a schema collision.
- The drift check compares parsed JSON, because a Windows checkout holds `openapi.json` with CRLF endings.
- Left out of the spec on purpose, and listed in the test: SCIM v2 (clients implement RFC 7644), OAuth and OIDC browser redirects, and huma's own docs, spec and schema routes.
- `TestSpecMerge_CombinesHumaAndSpecOnly` now checks the served spec instead of merging by hand, because the served spec already holds both sets. The unused `GENERATE_MERGED_SPEC` output went with it.

## Gotchas

- Security schemes are not declared yet, so the spec does not yet say how to authenticate.
- Running a typed client against the real stack showed API key auth failing under `simple_protocol`, the production query mode that the test suite does not use. That is a separate fix.

## Quality checks

- `go test ./internal/api/` passes, `vue-tsc --build` passes against the regenerated types.
- Not tested: a Go client from `oapi-codegen`. Auto mode refused running the tool, so the requirement's acceptance step is still open.
