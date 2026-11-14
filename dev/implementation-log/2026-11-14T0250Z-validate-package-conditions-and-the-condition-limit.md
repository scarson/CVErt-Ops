# Validate package conditions and the 100-condition limit

## What was built

MATCH-2 plan Task 2.4 (design sections 3.2, 4.2 and 8). `internal/alert/dsl/validator.go`:

- More than 100 conditions is a rule-level error, `a rule may hold at most 100 conditions`. `Compile` returns an error for the same case, so a stored rule edited past the limit fails closed (`failUncompilableRule`).
- `affected.package` `eq` with an empty or whitespace-only value, or `in` holding one, is refused at that index (`value must not be empty`); `in` with no values or `null` is refused (`value must list at least one item`). Other fields keep accepting an empty `in`.
- An `and` rule with a package condition and two or more `eq`/`in` ecosystem conditions that no ecosystem satisfies together is a rule-level error with the design's message. `{ecosystem in [npm, PyPI], ecosystem eq npm}` and `{ecosystem eq Debian, ecosystem eq Debian:13}` are allowed.
- `affected.package` `eq`/`in` in an `or` rule, or in an `and` rule with no `eq`/`in` ecosystem condition, gets the design's warning about narrowing by ecosystem first.

## Key decisions

- **The never-matching check is linear.** A value `v` matches a stored ecosystem `s` when `s == v`, or `v`'s base takes a suffix and `s` starts with `v + ":"`. Matches are colon-prefix cones, so trying each distinct value `w` as the stored ecosystem is exact; a condition holds for `w` when its value map holds `w` or a colon-prefix of `w` (when the base takes a suffix). Cost is values × conditions × colons, not values squared.
- **An unparseable ecosystem condition skips the never-matching check**: `validateValue` already reports it, and a second, derived error would be noise.
- **A negative ecosystem condition does not count as narrowing**: `{ecosystem neq npm, package eq lodash}` gets the warning, matching design section 8 ("no `affected.ecosystem` condition with `eq` or `in`").
- Warnings still reach callers only through the validate endpoint and alongside blocking errors on create and PATCH, as before.

## Gotchas

- The create/PATCH symmetry test was checked to fail with the correlation check disabled (create returned 202), then restored.

## Quality checks

- Added in `internal/alert/dsl/dsl_test.go`: `TestValidate_ConditionLimit` (100 pass, 101 refused at index -1, `Compile` errors), `TestValidate_PackageEmptyValues`, `TestValidate_EmptyInOnOtherFieldsUnchanged`, `TestValidate_NeverMatchingEcosystems`, `TestValidate_NeverMatchingEcosystemsLargeLists` (two lists of 30,000 releases; the package's tests run in about a second), `TestValidate_PackageMatchWithoutEcosystemWarns`.
- Added `TestAlertRule_NeverMatchingEcosystemsSameErrorsOnCreateAndPatch` in `internal/api/alert_rules_test.go`: 422 with the same error list from create and PATCH.
- `go test ./internal/alert/dsl/... -count=1`: pass.
- `go test ./internal/api/... -count=1 -run AlertRule`: pass (35 tests).
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues (one staticcheck De Morgan finding fixed).
