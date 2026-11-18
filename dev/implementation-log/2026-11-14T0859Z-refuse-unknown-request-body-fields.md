# Refuse request body fields the endpoint does not define

## What was built

| Feature | Files | Description |
|---|---|---|
| Strict body decoding | `internal/api/contract.go` (`decodeJSON`, `withoutSchemaLink`, `bodyLocation`) | `decodeJSON` decodes with `encoding/json/v2` and `RejectUnknownMembers(true)`. An object member the body struct does not define gets 422 `validation failed` with one error, `unexpected property` at `body.<path>` (for example `body.items[1].idd`), which is the problem huma writes for its own operations. Any other decode failure keeps the 400 `invalid request body`. `decodeJSON` now writes the problem itself and returns a bool, so its callers no longer choose the status. |
| Callers | 32 call sites in 15 files in `internal/api` | Each now reads `if !decodeJSON(w, r, &req) { return }`. `admin_orgs.go` previously wrote a bare 400 `invalid JSON body`; it now writes the same problem as the others. |
| Tests | `internal/api/contract_test.go`, `alert_rules_test.go`, `auth_test.go` | Unit tests for decodeJSON: unknown member at top level, in another case, in a nested object, in an array element, with a numeric name, and `$schema` inside a nested object; trailing data; `$schema` at top level accepted. `TestCreateAlertRule_UnknownFieldRefused`: `watchlist_id` for `watchlist_ids` gets 422 at `body.watchlist_id` and creates no rule. `TestLoginUnknownFieldRefused`: a huma operation refuses an unknown member with the same problem and accepts `$schema`. `TestAlertRule_NoFireOnNonMaterialChanges` now expects the removed field to be refused. |

## Key decisions

- **`encoding/json/v2` rather than v1 `Decoder.DisallowUnknownFields`.** v1 reports only `json: unknown field "x"`, with no path, so a misspelled member of a nested object or array element (the version check's `items[]`) could not be located. v2 is in the default Go 1.27 build and reports the JSON Pointer of the unknown member. v2 also matches member names case-sensitively, as the published schemas and huma's validator do, so `{"Name": ...}` is now refused where v1 matched it to `name`. It also refuses a second JSON value after the body, duplicate member names and invalid UTF-8, all of which v1 accepted or ignored.
- **Top-level `$schema` is accepted and ignored.** huma's `SchemaLinkTransformer` adds a read-only `$schema` property to every published request schema, and huma operations accept it. Refusing it on chi handlers would make the server disagree with its own schema, so `withoutSchemaLink` removes that one member before the strict decode. A `$schema` member in a nested object is refused, as huma refuses it there.
- **SCIM protocol handlers stay tolerant.** `scim_users.go` and `scim_groups_handler.go` decode with their own `json.NewDecoder` calls. RFC 7643/7644 clients send members such as `schemas` and extension attributes that the handlers do not model, so they are not changed. `scim_admin.go` (CVErt Ops' own SCIM configuration API) uses `decodeJSON` and is now strict.
- **Nested raw JSON is unchanged.** Members typed `json.RawMessage` (alert-rule `conditions`, channel `config`) are decoded later by their own code, which this change does not touch.

## Gotchas discovered

- A fresh worktree has no `web/dist`, so `internal/api` fails at setup; copied from the main checkout as the CLAUDE.md rule says.
- In a JSON Pointer only the last token is known to be a member name; a numeric token before it is taken as an array index, which holds because no request struct has numeric member names.

## Quality checks

- `TestCreateAlertRule_UnknownFieldRefused` failed on the old code (`got 202, want 422`) before `decodeJSON` changed, and passes after.
- The SPA (`web/src`) sends no field the server does not define; bodies built in a separate variable (groups, watchlists, watchlist items, register), which TypeScript's excess-property check does not cover, were compared with the server structs by hand.
- `go test ./internal/api/ -count=1`: the only failure was `TestAlertRule_NoFireOnNonMaterialChanges` before its update; it passes after.
- `go test ./... -count=1 -timeout=600s`: all 43 packages pass (4 have no tests).
- `golangci-lint run --allow-parallel-runners ./internal/api/...` (v2.15.0): 0 issues.
