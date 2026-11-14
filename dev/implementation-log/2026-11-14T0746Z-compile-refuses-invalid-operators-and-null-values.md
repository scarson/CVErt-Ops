# Compile refuses invalid operators and null values

## What was built

| Feature | Files | Description |
|---|---|---|
| Operator check in Compile | `internal/alert/dsl/compiler.go` | `Compile` refuses any condition whose operator the field registry (`fields` in `field.go`) does not list for its field, with the message `Validate` uses (`msgInvalidOperator`, now shared). Before, such a stored rule compiled to other SQL: `severity gte "high"` and `severity contains` to `lower(cves.severity) <> ?`, `in_cisa_kev neq true` to `= ?`, `fts_query eq` to an FTS match, `cvss_v3_score regex` to a post-filter. |
| Null scalar values refused | `internal/alert/dsl/validator.go`, `compiler.go`, `sets.go` | `decodeScalar` decodes a condition's single value and refuses JSON `null`, which `json.Unmarshal` accepts by leaving the zero value. `Validate` and `Compile` both decode single values through it: numeric, time, bool, string/enum `eq`/`neq`, text, regex, FTS, and the `eq`/`neq`/substring values of `affected.*` fields (`conditionValues`, package substring match). `cvss_v3_score gt null` had compiled to `> 0`, and `description_primary contains null` to `ILIKE '%%'` (every CVE). |
| Tests | `internal/alert/dsl/operator_value_refusal_test.go`, `internal/api/alert_rules_test.go` | `TestCompile_RefusesOperatorNotValidForField` (every field, every operator it does not take: `Validate` and `Compile` both refuse with the same message), `TestCompile_RefusesStoredOperatorsSeenCompilingWrongly` (the four rules the MATCH-2 review found), `TestValidateCompile_RefuseNullScalarValue` (19 field and operator pairs); a "null numeric value" case in `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` |

These fix two findings recorded under Discoveries in `dev/plans/2026-11-13-product-match-rules-plan.md` (stored rules with operators `Validate` refuses compile to wrong SQL; `cvss_v3_score gt null` validates). PLAN.md §10.5 (fail-closed policy) requires a stored rule with an operator the compiler does not accept to fail closed; the evaluator then sets it to `status=error` (`failUncompilableRule`).

## Key decisions

- The null refusal covers every single-value condition, not only numeric fields: the cause is the same decode in every kind, and a null text or regex value matched every CVE. JSON `null` for an `in`/`not_in` list keeps its MATCH-2 meaning (an empty list), because `in null` matching nothing and `not_in null` matching everything is the intended reading (plan Deviations, Task 2.3).
- `Validate`'s message for a null value is the kind's existing message with the reason appended, for example `value must be a number: null is not allowed`.

## Existing tests changed

- `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` now raises the test org's API rate limit (`tier_overrides`), as `alert_events_expand_test.go` does: its fifth case made 11 org requests, past the free tier's burst of 10.

## Meaning change for stored rules

A stored rule holding an invalid operator or a null single value, reachable only by editing the database, now fails to compile and is set to `status=error` on its next evaluation instead of matching by the wrong SQL.

## Quality checks

- The new DSL tests failed first (Compile accepted every invalid operator and null value; Validate accepted the nulls), then passed.
- `go test ./internal/alert/dsl/ -count=1`: pass. `go test ./internal/api/ -run TestAlertRule_ValidationErrorsSameOnCreateAndPatch -count=1`: pass.
- golangci-lint v2.15.0 on `./internal/alert/... ./internal/api/...`: 0 issues.
