# Check package exports name lookups and index expressions for rule matching

## What was built

MATCH-2 plan Task 1.1. `internal/check` now exports what the alert DSL compiler needs to build product sets, because the compiler cannot import `internal/store` (which imports `internal/alert/dsl`):

- `CPEIndexExpr` and `CNANameIndexExpr`, the expressions `cve_cpe_matches_check_idx` and `cve_cna_affected_check_idx` index, moved from `internal/store/check.go` with their doc comments. The store's version check statements call them from `internal/check`.
- `CNANameKeyFor` (was `cnaNameKey`), `OtherProductsFor` (the `otherProducts` lookup by `ProductRef`) and `IsOtherProduct` (was `isOtherProduct`).

## Key decisions

- `CNANameIndexExpr` takes its length from `cnaNameRunes` instead of a hard-coded `256`. `TestIndexExpressions` pins both expressions to the exact text the store emitted before, so the version check statements are byte-for-byte unchanged.
- `internal/store/export_test.go` no longer aliases the two helpers; `check_index_test.go`, which pins them to the migrations, calls the `internal/check` functions directly.

## Quality checks

- `go test ./internal/check/... -count=1`: pass.
- `go test ./internal/store/... -count=1 -run Check` (testcontainers): pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
