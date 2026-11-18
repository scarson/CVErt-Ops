# Generated Go client compiles from the served spec

## What was built

- Named Go types for 13 anonymous admin bodies in `internal/api/openapi_spec.go`, shared where operations return the same shape (`adminJobResponse`, `adminFeedStateResponse`, `adminUserStatusResponse`).
- `testChannelResponse` and `nlSearchResponse` are now `testChannelResult` and `nlSearchResult`.
- `TestOpenAPISpec_SchemaNamesFitGeneratedClients` requires plain schema names and rejects a schema with the name `oapi-codegen` gives an operation's own type.
- `openapi.json` and `web/src/lib/api/schema.d.ts` regenerated. Only schema names changed, and wire formats did not.

## Key decisions

- Fixed in the spec, not with `oapi-codegen`'s `resolve-type-name-collisions` option. The requirement is a client generated with no hand edits, and every future client would otherwise need to know about the option.
- Named types, not a custom huma schema namer. A namer would not cover the two named types that collided, and the guard test catches a new anonymous body.

## Gotchas

- huma names an anonymous response body `<OperationID>Response`, for example `Admin-versionResponse`. `oapi-codegen` removes the hyphen and gets `AdminVersionResponse`, the name of its client wrapper for that operation.
- An exact comparison of schema names finds only the 2 collisions without hyphens. The Go compiler reported 14.

## Quality checks

- `oapi-codegen` v2.8.2 against the 3.0 document served by a local production stack: 14 redeclared types before the fix, and the package builds after it.
- The generated client called the real stack with only an API key: CVE search, detail and sources, rule validate, create, list and dry-run, watchlist create, item add and remove. A round-trip comparison of each raw response against its generated type found no differences. Its alert event list was empty, so that item shape was not compared.
- `go test ./internal/api/`, `golangci-lint run ./internal/api/...` and `vue-tsc --build` pass.
