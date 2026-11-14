# Refuse unknown keys in alert DSL rules and conditions

## What was built

| Feature | Files | Description |
|---|---|---|
| Strict DSL parse | `internal/alert/dsl/parser.go` | `Parse` decodes with `encoding/json/v2` and `RejectUnknownMembers(true)`. A key that the rule object or a condition does not define returns `*dsl.UnknownKeyError{Index, Key}`; `Index` is the condition's position, or -1 for a key of the rule object. Keys are matched case-sensitively. A condition's `value` stays raw JSON for `Validate`. |
| Alert rules | `internal/api/alert_rules.go` (`parseDSL`) | Create and PATCH answer 422 `unexpected property` at `body.conditions[i].<key>`; the validate endpoint returns `{index: i, field: <key>, message: "unexpected property"}`. |
| Saved searches | `internal/api/saved_searches.go` (`validateDSL`) | Create and PATCH answer 422 `unexpected property` at `body.query_json.conditions[i].<key>`, or `body.query_json.<key>` for a key of the query object. `validateDSL` now returns the error detail instead of a message and status; both returns were already 422. |
| Tests | `internal/alert/dsl/dsl_test.go`, `internal/api/alert_rules_test.go`, `internal/api/saved_searches_test.go` | `TestParse_UnknownKey` (extra key, misspelled key in a later condition, key in another case, key of the rule), `TestParse_ObjectValueKeysNotChecked`, `TestAlertRule_UnknownConditionKeyRefused` (create, PATCH, validate), `TestSavedSearch_UnknownQueryKeyRefused` (condition key on create, query key on PATCH). |

## Key decisions

- **Why.** `conditions` is passed through the request-body decoder as raw JSON, so the strict `decodeJSON` from the previous entry did not reach it, and v1 `json.Unmarshal` in `Parse` dropped unknown keys. A condition defines only `field`, `operator` and `value`. A misspelled one of those usually fails `Validate` anyway (an empty operator or a missing value), but an extra key such as `"negate": true` was silently dropped, saving a rule that matches the opposite of what its writer meant.
- **One place.** All four callers of `dsl.Parse` get the check: alert-rule create, PATCH and validate (through `parseDSL`); saved-search create and PATCH; running a saved search (stored `query_json`); and AI search. The AI search path already constrains Gemini's output to `field`, `operator` and `value` with a response schema (`internal/ai/gemini.go` `buildDSLResponseSchema`), so strictness there should not add failures; if Gemini did add a key, the request now fails with the existing 502 instead of running a query with the key dropped.
- **Stored rules are not re-checked.** The evaluator (`internal/alert/evaluator.go` `loadAndCompileRule`) reads stored conditions with v1 `json.Unmarshal` and does not call `Parse`; rules are checked when written. A saved search runs its stored `query_json` through `Parse`, so a stored query with an unknown key would now fail to run. Unknown keys could only have been stored before this change; the project has no users yet.
- **v2 for this parser** follows Sam's approval of `encoding/json/v2` for request input (2026-11-14). The wider move of the codebase to v2 is a separate plan.

## Gotchas discovered

- PATCH on a rule created with `enabled: true` answers 409 while the rule is `activating`; a test that PATCHes straight after create needs a disabled rule (201).

## Quality checks

- `TestParse_UnknownKey` failed on the old parser (all four cases returned nil); `TestAlertRule_UnknownConditionKeyRefused` and `TestSavedSearch_UnknownQueryKeyRefused` failed before the API mapping (the key was refused only at `body.conditions` / `body.query_json`, with the parser's message). All pass after.
- `go test ./internal/alert/dsl/ -count=1`: pass. `go test ./internal/api/ -run 'TestAlertRule|TestCreateAlertRule|TestSavedSearch|TestValidate|TestNLSearch|TestAI'`: pass.
- `go test ./... -count=1 -timeout=600s`: all 43 packages pass (4 have no tests).
- `golangci-lint run --allow-parallel-runners ./internal/api/... ./internal/alert/...` (v2.15.0): 0 issues.
