# Limit set conditions in "and" rules to 10

## What was built

| Feature | Files | Description |
|---|---|---|
| Set-condition limit | `internal/alert/dsl/validator.go` | `tooManyAndSets` counts an `and` rule's set conditions: every `affected.cpe_product` condition, every `affected.package` condition, and every `affected.ecosystem` `eq`/`in` condition when the rule has no `affected.package` condition. Over 10, `Validate` adds a rule-level error (index -1): `an "and" rule may hold at most 10 product, package and ecosystem conditions; list more values in one "in" condition, or use an "or" rule`. `or` rules are not limited. |
| Stored rules fail closed | `internal/alert/dsl/compiler.go` | `Compile` refuses the same rules, after the 100-condition check. |
| Tests | `internal/alert/dsl/dsl_test.go`, `internal/api/alert_rules_test.go` | `TestValidate_AndSetConditionLimit`; a case in `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` |

The rule is MATCH-2 design section 17 (`dev/plans/2026-11-13-product-match-rules-design.md`), approved by Sam. Under `and` each set stays its own `IN` (pitfall DB-27), and realtime planning against one CVE on the 2.6 M-CVE ingest grew with them: 10 sets 4.3 ms (within the 5 ms realtime threshold), 20 sets 15.9 ms, 50 sets 74 ms. Realtime evaluates every organisation's rules on each changed CVE.

## Key decisions

- Beside a package condition, `eq`/`in` ecosystem conditions are folded into every package set (`correlationFor`) and add no set, so they do not count. Negative ecosystem conditions compile to a correlated `NOT EXISTS` scalar, not a set, and do not count.
- `TestValidate_AndSetConditionLimit` covers 10 and 11 of each kind, a substring package condition counting, ecosystem conditions beside a package not counting, negative ecosystem and scalar conditions not counting, and an `or` rule of 50 set conditions passing; each case checks that `Compile` agrees.

## Existing tests changed

- `TestValidate_ProductLimit` (`dsl_test.go`), case "100 conditions each listing the same 50 products": now an `or` rule. It tests the product limit, and as an `and` rule it also hit the set limit. The table gained a `logic` column.
- `TestCompile_ProductStoredRuleFailsClosed` (`sets_test.go`), case "100 conditions of the same 50 values": now an `or` rule, for the same reason (Compile refused it by the set limit first).
- `TestAlertRule_ValidationErrorsSameOnCreateAndPatch` (`internal/api/alert_rules_test.go`): the "51 products" case is now an `or` rule; the case table gained a `logic` column and a case of 11 product conditions under `and`.
- `TestCompile_WorstRuleStaysUnderTheParameterLimit` (`sets_test.go`), rewritten: its rule of 50 product and 50 package conditions under `and` is no longer accepted. The worst accepted rule is now 10 `affected.package` `in` conditions beside 90 `affected.ecosystem` `in` conditions, each naming a release and PyPI: every package set carries all 90 ecosystem lines, so it binds 1 + 90 x 2 + 2 = 183 arguments, 1,830 in all with a 5,000-ID chunk (was 700). A product set binds 11 whatever its values.
- The kept-ingest measurement harness (`internal/alert/kept_ingest_*_test.go`, build tag `keptingest`) still builds `and` rules of more than 10 set conditions; it is unchanged, and those rows would now be refused by `compileMeasured`'s validation.

## Pitfall check

`/pitfall-check` on `internal/merge/pipeline.go` and `internal/alert/dsl/validator.go`: no issues. The re-check stamp in `migrateCVEPK` is one `UPDATE` inside the advisory-locked merge transaction, with no loop, `defer` or outbound call; the validator changes hold no SQL, and `productValues` now stops at the first refused value. The set limit keeps `and` rules within the planning cost DB-27 measures.

## Quality checks

- `TestValidate_AndSetConditionLimit` failed first (no error and Compile accepted for every refused case), then passed.
- `go test ./internal/alert/dsl/... -count=1`, `go test ./internal/alert/... -count=1`: pass.
- `go test ./internal/api/... -count=1 -run 'AlertRule|SavedSearch|AI'`, `go test ./internal/store/... -count=1 -run DSL`: pass.
- `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
