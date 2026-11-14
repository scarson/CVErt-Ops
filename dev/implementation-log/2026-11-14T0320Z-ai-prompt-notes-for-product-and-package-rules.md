# AI prompt notes for product and package rules

## What was built

MATCH-2 plan Task 3.4 (design section 10). `internal/ai/schema.go` adds three lines to the AI search prompt's notes, after the existing ones:

- `"affected.cpe_product"` takes `"vendor:product"` from a CPE name, such as `"nodejs:node.js"`.
- In an `"and"` rule, `"affected.ecosystem"` and `"affected.package"` describe the same package, so name the package's ecosystem with it.
- `"affected.package"` with `"eq"` matches a whole package name.

The field list already carries `affected.cpe_product (type: CPE vendor:product)` with operators `eq` and `in` from `dsl.ExportFieldDescriptions` (Task 3.1). `PromptVersion` is a hash of the prompt, so it changes by itself; no test pins its value.

## Quality checks

- New `TestBuildSchemaDescription_ProductAndPackageNotes` in `internal/ai/schema_test.go`: the field line and the three notes, verbatim.
- End of Phase 3: `go test ./internal/alert/... ./internal/ai/... -count=1`: pass (`internal/alert` 163, `internal/alert/dsl` 198, `internal/ai` 34 tests and subtests); the only error-level log lines are the two fan-out failures existing tests inject on purpose.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
