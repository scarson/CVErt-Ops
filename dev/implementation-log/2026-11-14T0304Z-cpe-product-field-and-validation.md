# The affected.cpe_product field and its validation

## What was built

MATCH-2 plan Task 3.1 (design sections 3.1, 3.2, 5.2 and 8). The alert DSL registers `affected.cpe_product`:

- New field kind `kindProduct` with operators `eq` and `in`; `ExportFieldDescriptions` gives it `TypeDesc` `CPE vendor:product`. It joins `selectiveFields`, so a regex rule with a product condition needs no watchlist.
- `validateValue` checks the JSON shape (`eq` a string, `in` an array of strings), refuses an empty or `null` `in` list (`value must list at least one item`), and reports `check.ParseProductValue`'s message for each refused value at the condition's index.
- `validateProducts` (rule level) sums each product condition's normalised, de-duplicated values and refuses more than 50 (`a rule may name at most 50 products in total`, index -1). It warns, at the condition's index, for each value the name table does not map, naming the first CNA name `check.NamesFor` returns (the CPE's own vendor and product with `_` read as a space and escapes dropped).
- `productValues` (in `validator.go`) parses and de-duplicates one condition's values. `Compile` will count with the same function (Task 3.2), so both apply the same limit.

## Key decisions

- **Per-condition count, summed.** Sam's ruling (2026-11-14): the same product in two conditions counts twice, because each condition compiles to its own set with its own parameters. A count of distinct values across the rule would let 100 conditions each list the same 50 products.
- **The warning quotes the value as written**, not with `%q`, which would double a backslash in a value such as `1und1:1\&1_online_storage`. Values are printable ASCII by the parser's check, so nothing unprintable reaches the message.
- **A value that fails to parse is not counted** towards the 50; it already has its own error.

## Gotchas

- Until Task 3.2, `Compile` refuses the field ("unsupported field kind"), which fails closed for any stored rule.

## Quality checks

- New tests in `internal/alert/dsl/dsl_test.go`: every section 8 message row for the field, valid values (case, `\.`, `\&`, 255 characters), the refused operators, the unmapped-product warning (absent for both Node spellings), the 50-product limit (50 pass, 51 fail, duplicates after normalisation count once, the same product in two conditions counts twice, 100 conditions of the same 50 products refused), and a regex rule with a product condition. `TestExportFieldDescriptions` now also checks the field and its type.
- `internal/api/alert_rules_test.go`: the create/PATCH symmetry test is now table-driven (`TestAlertRule_ValidationErrorsSameOnCreateAndPatch`); besides the never-matching ecosystems case it covers 51 products and the malformed value `nodejs node.js`, each asserting the exact error list and PATCH equal to create.
- `go test ./internal/alert/dsl/... -count=1`: pass. `go test ./internal/api/... -count=1 -run AlertRule`: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
