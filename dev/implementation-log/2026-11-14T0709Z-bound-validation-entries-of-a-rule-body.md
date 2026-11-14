# Bound the validation entries a rule body can produce

## What was built

| Feature | Files | Description |
|---|---|---|
| One value error per product condition | `internal/alert/dsl/validator.go`, `internal/alert/dsl/compiler.go` | `productValues` stops at the first value `check.ParseProductValue` refuses and returns that one error (it returned one error per refused value). `validateValue` reports it with the same message and index as before; `compileProducts` returns it, as it already returned the first. |
| Warnings only within the product limit | `internal/alert/dsl/validator.go` | `validateProducts` counts every product condition first. Over the 50-product limit it returns only the rule-level limit error; within it, one unmapped-product warning per unmapped product, so at most 50. |
| Tests | `internal/alert/dsl/dsl_test.go` | `TestValidate_ProductValueErrorsBounded`, `TestValidate_ProductWarningsWithinLimit` |

Before this change a 1 MiB rule body could produce 333,334 product value errors or 107,000 unmapped-product warnings, each an entry in the 422 response. The messages are those of MATCH-2 design section 8 (`dev/plans/2026-11-13-product-match-rules-design.md`), unchanged.

## Key decisions

- A product condition with a refused value is not counted toward the 50-product limit and gets no warnings: its values after the refused one are not parsed, so a count of the rest would be partial. A rule with a bad value and too many products now reports the value error alone; the limit error appears once the value is corrected.
- Compile already failed on a condition's first refused value, so Validate and Compile still refuse the same rules.
- No existing test assumed one error per refused value in a condition; none changed. Other per-value errors (an `affected.ecosystem` or enum `in` list of invalid values) are outside this change.

## Quality checks

- Both tests failed first (99,999 entries for the bad-value list; 51 and 100,000 warnings over the limit), then passed.
- `go test ./internal/alert/dsl/... -count=1`: pass.
- `go test ./internal/api/... -count=1 -run 'AlertRule|SavedSearch|AI'` (includes `TestAlertRule_ValidationErrorsSameOnCreateAndPatch`): pass.
- `go test ./internal/store/... -count=1 -run DSL`: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
