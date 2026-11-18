# Stored alert-rule conditions fail closed on unknown keys

## What was built

| Feature | Files | Description |
|---|---|---|
| `dsl.ParseConditions` | `internal/alert/dsl/parser.go` | Decodes a stored conditions array with `decodeOptions` (encoding/json/v2 defaults plus `RejectUnknownMembers`), the one options value `Parse` also uses. An unknown or case-variant key returns `*UnknownKeyError{Index, Key}`; `null`, `[]`, a non-array, and an element that is not an object are refused. It checks no field names, operators or values. Commit `b25569b`. |
| Shared error mapping | `internal/alert/dsl/parser.go` (`decodeError`, `unknownKeyError`) | `unknownKeyError` takes the pointer tokens of the conditions array (`["conditions"]` for `Parse`, none for `ParseConditions`), so one helper locates `/conditions/<i>/key` and `/<i>/key`. `Parse`'s behaviour and tests are unchanged. |
| Evaluator | `internal/alert/evaluator.go` (`loadAndCompileRule`) | Decodes `rule.Conditions` with `dsl.ParseConditions` instead of v1 `json.Unmarshal`. The error reaches the existing fail-closed paths: realtime and batch/EPSS call `failUncompilableRule` (log with `rule_id`, `status='error'`, continue with the next rule); activation sets `error` from `activating` and returns the error; dry-run returns it. Commit `db003c3`. |
| Tests | `internal/alert/dsl/dsl_test.go`, `internal/alert/stored_conditions_test.go` | `TestParseConditions_*`: valid array, unknown/case-variant/misspelled keys with their index, and ten refused inputs (`null`, `[]`, `{}`, `"x"`, `[null]`, `[1]`, `["x"]`, `[[]]`, a trailing `null` element, `not json`). `TestEvaluateBatch_StoredConditionWithUnknownKeyFailsClosed` seeds the corpus, writes three rules through `Store.CreateAlertRule` (bypassing API validation), runs `EvaluateBatch` once, and checks: the control rule (`severity in [critical]`) stays active with one event per non-retracted critical CVE (14); the `"negate"` and `"Field"` rules are `error` with 0 events; the log names each rule ID and key and holds no condition value. |

## Key decisions

- **Pointer elements for null.** v2 decodes JSON `null` into a struct as its zero value without error, so `ParseConditions` decodes into `[]*Condition` and refuses a nil element. `Compile` would also refuse it (unknown field `""`), but the parse error names the problem.
- **One run of `EvaluateBatch`.** The batch cursor advances after the first run, so the control and failing rules are evaluated in the same run.

## Gotchas discovered

- Before the change, the `"negate"` and `"Field"` rules each produced the same 14 alert events as the control rule (v1 ignored `negate` and case-folded `Field`).

## Quality checks

- Red: the integration test failed with both rules `active`, 14 events each, nothing logged; the DSL tests failed to build (`undefined: dsl.ParseConditions`).
- `go test ./internal/alert/dsl/ -count=1`: pass (221 top-level tests).
- `go test ./internal/alert/ -count=1`: pass (94 top-level tests); no existing fixture needed a change.
- `golangci-lint run --allow-parallel-runners ./internal/alert/...`: 0 issues.
- Writers of `alert_rules.conditions`: only `Store.CreateAlertRule` and `Store.UpdateAlertRule`, called only from `internal/api/alert_rules.go` create and PATCH, which pass the conditions through `parseDSL` → `dsl.Parse` first. No migration writes conditions.
- Full suite not run (the coordinator runs it once per phase).
