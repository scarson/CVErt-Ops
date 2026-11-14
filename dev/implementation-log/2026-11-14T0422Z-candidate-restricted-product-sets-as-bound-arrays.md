# Candidate-restricted product sets match against bound arrays

## What was built

| Feature | Files | Description |
|---|---|---|
| Bound-array product set | `internal/alert/dsl/sets.go` | With candidate IDs, a product set is two fixed-text branches: `cve_cpe_matches` rows among the candidates with `cpe_normalized ^@ ANY($prefixes)`, and `cve_cna_affected` rows among the candidates joined to `unnest()` of name vendors, products, prefix flags and group numbers, minus rows that are an other product of the same group (`NOT EXISTS` over `unnest()` of the other products, with `check.IsOtherProduct`'s ASCII boundary). Eleven parameters whatever the number of values. `productArrays` is built once per condition in `Compile`; `productSet` returns the closure that picks the bound-array form with candidates and the range form without. `ProductSetSQL` keeps its signature and follows the same rule. |
| One product branch pair under "or" | `internal/alert/dsl/types.go`, `compiler.go` | `Compile` builds `orProducts`, the arrays of every product condition of an `or` rule with groups numbered across all values. `CompiledRule.Where` with candidate IDs puts its two branches where the first product condition's would be and skips the other product conditions' own branches. Under `and` each product condition keeps its own branches. Package and ecosystem conditions are unchanged. |
| Tests | `internal/alert/dsl/sets_test.go`, `where_golden_test.go`, `testdata/where.golden`, `internal/alert/product_candidate_form_test.go`, `product_match_test.go` | Unit tests pin the exact SQL and arrays of an `or` rule of `nodejs:node.js` and `in [microsoft:.net, microsoft:.net_framework]`, check that 1 and 50 products under `or` give the same SQL and 11 arguments with no CPE or CNA index range, check `and` keeps one set per condition, and check `ProductSetSQL` picks its form by candidates. A new golden entry pins an `or` rule of two product conditions, a package and severity. The integration test runs 13 product rules (`and`, `or`, mixed with each other and with scalars) over the seeded corpus plus hand-built CNA and CPE rows, with no candidate IDs, with all CVE IDs, and in pages of two, and requires equal answers and named matches and non-matches. The 257-character full-name recheck test runs both forms. |
| Pitfall | `dev/implementation-pitfalls.md` | DB-27 records the candidate-path planning cost and the bound-array form; its fix and checklist line now distinguish the two settings. |

## Key decisions

- **Sam's decision for the MATCH-2 Phase 4 gate**: with candidate IDs, a 50-product, 50-package `or` rule planned in 16 to 20 ms for one CVE and 2.0 s for a 5,000-ID batch, growing with the OR-ed range and name terms and with each copy of the candidate array. Rows on the candidate paths are reached through `cve_id = ANY(candidates)`, so the check indexes are not needed there; without candidate IDs (dry-run, saved searches) the range form stays, unchanged byte for byte (golden file entries without candidates did not change).
- The forms are equivalent: the range form's `starts_with` recheck alone decides a CPE match and implies its index range; exact names are rechecked whole in both forms; a prefix name's range on the first 256 characters equals `starts_with` because prefix names come only from the name table and are short; other products exclude by group, as the range form's per-value groups do. The comment on `productArrays` records this.
- Merging an `or` rule's product conditions is exact because OR of set memberships is membership in the union, and groups keep each value's other products to its own names.
- The golden file's candidate renderings of the three rules with product conditions changed, as intended; the renderings without candidates and every rule without products are unchanged.
- Every array slice is non-nil (`pq.Array(nil)` binds NULL); casts (`::text[]`, `::boolean[]`, `::int[]`) make the simple-protocol literals typed.

## Quality checks

- `go test ./internal/alert/dsl/... -count=1`: pass. The new unit tests failed first on range terms and 40 to 1,440 arguments where 11 were expected.
- `go test ./internal/alert/... -count=1`: pass. `go test ./internal/store/... -count=1 -run DSL`: pass. `go test ./internal/api/... -count=1 -run 'AlertRule|SavedSearch|AI'`: pass.
- Falsification: with `o.grp = n.grp` removed, the equivalence test failed for the `.NET` list rules (the bound-array form lost `.NET Framework`); restored, it passes.
- `go vet -tags keptingest ./internal/alert/`: clean. golangci-lint v2.15.0: 0 issues. `pitfall-check`: no issues.
- Not yet done: the bound-array form has not been explained or measured on the kept full ingest (pitfall DB-27).
