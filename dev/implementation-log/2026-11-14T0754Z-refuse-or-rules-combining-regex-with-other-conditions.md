# Refuse "or" rules that combine regex with other conditions

## What was built

| Feature | Files | Description |
|---|---|---|
| Refusal at save and compile | `internal/alert/dsl/validator.go`, `compiler.go` | `orMixesRegex` reports an `or` rule holding a `regex` condition beside a condition of any other operator. `Validate` adds a rule-level error (index -1), `an "or" rule cannot combine regex conditions with other conditions, because a regex is checked only on CVEs the other conditions match; put the regex conditions in a rule of their own`, and `Compile` refuses a stored rule of that shape, so the evaluator sets it to `status=error`. |
| PLAN.md | `PLAN.md` §10.2 | The regex execution constraints state the refusal; the case-insensitivity paragraph says how pattern flags override `(?i)`; a new "Values and operators" paragraph records the null refusal and Compile's operator check from the first commit of this branch. |
| Tests | `internal/alert/dsl/regex_rules_test.go`, `internal/alert/evaluator_test.go`, `internal/api/alert_rules_test.go` | `TestValidateCompile_OrRuleMixingRegexIsRefused` (with and without a watchlist), `TestValidateCompile_OrRuleOfOnlyRegexWithWatchlist`, `TestEvaluator_StoredOrRuleMixingRegexFailsClosed` (dry-run returns the compile error; realtime records no event and sets the rule to `error`); a case in `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` |

This fixes a finding recorded under Discoveries in `dev/plans/2026-11-13-product-match-rules-plan.md` (`/plan-check`, Task 6.2): an `or` rule with a regex condition behaved as `and`. The SQL prefilter ORs the rule's SQL conditions and cannot include the regex, and `ApplyPostFilters` under `or` then keeps only candidates some regex matches, so the rule matched (SQL conditions) AND (regexes).

## Key decisions

- Refuse rather than evaluate. PLAN.md §10.2 allows regex only as a post-filter on a selective SQL prefilter. Under `or`, the rule's other conditions do not bound the regex branch, so evaluating it correctly would mean running the regex over the whole corpus (or the whole watchlist) in Go, with each candidate also carrying whether its SQL conditions matched. That is the "scan the world in Go" the guardrail exists to prevent, and new code in `CompiledRule`, the evaluator's candidate query and the saved-search executor. A user can write the regex as its own rule.
- The refusal holds with a watchlist too: the rule would still read as `and` within the watchlist.
- An `or` rule of regex conditions alone stays valid with a watchlist: `Where` is then the watchlist alone, and `ApplyPostFilters` under `or` keeps a candidate any regex matches, which is the correct reading. Without a watchlist the regex-only check already refuses it.
- `ApplyPostFilters` is unchanged: with the mixed shape refused, its `or` reading is correct for every rule `Compile` accepts.

## Existing tests changed

- `TestApplyPostFilters_UsesORLogicForORRules` (`internal/alert/evaluator_test.go`), rewritten: it used `or` [cvss_v3_score gte 7, regex apache, regex windows] and asserted that CVE-ORPF-003 (CVSS 8.0, "Linux privilege escalation") does not match, which is the `and` reading; under `or` the CVSS condition matches it. The rule is now the two regex conditions bound to a watchlist of the three CVEs, the shape its unused `orRegexConds` constant described, and the assertions are unchanged.

## Meaning change for stored rules

A stored `or` rule that combines a regex with other conditions now fails to compile and is set to `status=error` on its next evaluation; before, it matched as an `and` rule. Its owner must split it. This is noted in the PR for Sam's decision on a `dsl_version` bump (PLAN.md §10.5).

## Pitfall check

`/pitfall-check` on `internal/alert/dsl/validator.go`, `compiler.go`, `sets.go`, `internal/alert/evaluator.go` and `internal/store/dsl_executor.go` (this branch's diff against `dev`): no issues. No SQL, loops or transactions changed apart from dropping `lower()` from one selected column; lists stay single bound arrays (DB-12); the rejected/withdrawn filter is unchanged; PATCH revalidates the merged rule (API-9); the regex `(?i)` default now meets ARCH-2.

## Quality checks

- `TestValidateCompile_OrRuleMixingRegexIsRefused` and `TestEvaluator_StoredOrRuleMixingRegexFailsClosed` failed first (no error; dry-run succeeded), then passed.
- `go test ./internal/alert/dsl/ -count=1`, the two evaluator tests above, and `go test ./internal/api/ -run TestAlertRule_ValidationErrorsSameOnCreateAndPatch -count=1`: pass.
- golangci-lint v2.15.0 on `./internal/alert/... ./internal/store/... ./internal/api/...`: 0 issues.
