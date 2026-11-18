# Regex conditions ignore case by default

## What was built

| Feature | Files | Description |
|---|---|---|
| Case-insensitive regex | `internal/alert/dsl/validator.go`, `compiler.go` | `compileRegex` decodes a regex condition's pattern, applies the 256-character limit, and compiles `(?i)` + pattern, as PLAN.md §10.2 (text operator case-insensitivity) requires. Flags the pattern sets itself come after `(?i)` and override it, so `(?-i)Apache` matches case-sensitively. `Validate` and `Compile` both call it. |
| Descriptions matched as stored | `internal/alert/evaluator.go`, `internal/store/dsl_executor.go` | The evaluator's candidate query selects `description_primary` without `lower()`, and the saved-search executor's `PostFilterField` returns it without `strings.ToLower`. |
| cve_id patterns validated | `internal/alert/dsl/validator.go` | `Validate` checks every regex condition's pattern through `compileRegex`. Before, it compiled only `description_primary` patterns, so an invalid `cve_id` pattern was saved and then failed to compile. |
| Tests | `internal/alert/dsl/regex_rules_test.go`, `internal/alert/evaluator_test.go`, `internal/store/dsl_executor_test.go` | `TestCompile_RegexIsCaseInsensitiveByDefault`, `TestCompile_RegexFlagsInPatternOverrideDefault`, `TestValidate_CVEIDRegexMustCompile`; realtime subtests `RegexUpperCaseLiteral` and `RegexPatternFlagsCaseSensitive` in `TestEvaluatorRealtime` |

This fixes a finding recorded under Discoveries in `dev/plans/2026-11-13-product-match-rules-plan.md` (`/plan-check`, Task 6.2): patterns compiled without `(?i)` and ran against a lower-cased description, so a pattern with an upper-case literal, such as `Apache`, never matched.

## Key decisions

- `(?i)` is always prepended rather than only when the pattern has no flag group. A pattern that sets other flags, such as `(?s)`, still ignores case; a pattern that wants case-sensitivity says so with `(?-i)`. This is how PLAN.md §10.2's "unless the user explicitly supplies flags" is read: the user's flags win where they conflict.
- The pattern is compiled once as written before the `(?i)` form, so an error message quotes only what the rule wrote.
- The description is no longer lower-cased: with `(?i)` it changes nothing for case-insensitive patterns, and it would make every `(?-i)` pattern with an upper-case letter fail.

## Existing tests changed

- `TestExecuteDSLQuery_PostFilterCaseInsensitive` (`internal/store/dsl_executor_test.go`), rewritten: it attached hand-built post-filters (no `(?i)`) and asserted that `Critical Buffer` does not match the lower-cased target. It now compiles each regex through `dsl.Compile` and checks a lower-case pattern, an upper-case pattern, and `(?-i)` patterns of the stored case (match) and another case (no match). Restoring the lower-casing in `PostFilterField` fails its two `(?-i)` cases.

## Meaning change for stored rules

A stored regex rule whose pattern has an upper-case letter now matches CVEs it never matched (before, it could match only text the lower-cased description cannot hold, which is nothing for a literal upper-case letter). A pattern already in lower case matches what it matched before. Patterns are not otherwise reinterpreted. This is noted in the PR for Sam's decision on a `dsl_version` bump (PLAN.md §10.5).

## Quality checks

- `TestCompile_RegexIsCaseInsensitiveByDefault` and `TestValidate_CVEIDRegexMustCompile` failed first, then passed. `RegexPatternFlagsCaseSensitive` failed against the lower-cased description (1 event, want 0), then passed.
- `go test ./internal/alert/dsl/ -count=1`, `go test ./internal/alert/ -run 'TestEvaluatorRealtime|DryRun|PostFilter' -count=1`, `go test ./internal/store/ -run TestExecuteDSLQuery -count=1`: pass.
- golangci-lint v2.15.0 on `./internal/alert/... ./internal/store/...`: 0 issues.
