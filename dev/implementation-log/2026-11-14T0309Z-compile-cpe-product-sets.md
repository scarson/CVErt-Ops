# Compile affected.cpe_product conditions to CVE-ID sets

## What was built

MATCH-2 plan Task 3.2 (design sections 3.2, 4.2, 5.1 and 5.2). `internal/alert/dsl/sets.go` gains two exported builders:

- `ProductSetSQL(values, candidateIDs)`: `cves.cve_id IN (SELECT m.cve_id FROM cve_cpe_matches m WHERE m.vulnerable ... UNION ALL SELECT a.cve_id FROM cve_cna_affected a WHERE ...)`. The NVD branch ORs one range per CPE spelling and part (`a`, `o`, `h`), de-duplicated across values, on `check.CPEIndexExpr("m.cpe_normalized")` with `starts_with` on the whole prefix. The CNA branch ORs one group per value: the value's name terms on `check.CNANameIndexExpr` with the full lower-cased names rechecked (vendor and product for an exact name, vendor for a prefix name), and, when the value has other products, `AND NOT (...)` for that group only. The candidate IDs are repeated inside both branches when the caller has them.
- `OtherProductSQL(vendorExpr, productExpr, others)`: vendor and product equal, or for a prefix `starts_with` plus `substr(product, char_length(prefix) + 1) !~ '^[a-z0-9]'`, the ASCII boundary `check.IsOtherProduct` uses.

`Compile` handles a product condition before the regex branch: `compileProducts` refuses an operator other than `eq`/`in`, any value `check.ParseProductValue` refuses, and an empty list; the condition's values come from `productValues` (shared with `Validate`), and the rule's summed count past 50 fails the compile. The predicate is a closure over the parsed values calling `ProductSetSQL`. Product sets are never correlated with package conditions.

## Key decisions

- **Every range, name, full name and other product is a bind argument**; only `internal/check`'s index expressions and fixed text are concatenated. A test checks no argument appears in the SQL text.
- **Other products are lower-cased in Go** before binding, as `check.CNAName.Matches` compares them, so the SQL and Go tests agree even if a table entry were written in mixed case. The table is lower case today, so the arguments are unchanged.
- **`ProductSetSQL` with no values returns `FALSE`**, so the exported function cannot emit `()`. `Compile` refuses an empty list before it is reached.
- Argument counts: `nodejs:node.js` binds 38 with no candidates (6 ranges of 3, 5 exact names of 4) and 40 with one candidate list. The worst rule the validator accepts (the name table's 10 CPE spellings and 40 unmapped values with `_` in vendor and product, each in its own condition, plus 50 `affected.package` `in` conditions) binds 1,590 arguments with a 5,000-ID candidate list: 360 for the mapped products, 25 for each unmapped one, 2 candidate arrays per product set and 3 arrays per package set.

## Quality checks

- New tests in `internal/alert/dsl/sets_test.go`: the Node argument counts, ranges and name arguments, with and without candidates; `microsoft:.net`'s `NOT` group and boundary tests; per-value exclusion for `in [microsoft:.net, microsoft:.net_framework]`; ranges de-duplicated across the two Node spellings; values only as arguments; stored rules that fail closed (malformed value, 51 values, 100 conditions of the same 50, empty list, `neq` and `regex` operators); the worst rule's argument count. `TestWhere_IsDeterministicAcrossCalls` gains a product rule.
- `go test ./internal/alert/dsl/... -count=1`: pass (198 tests and subtests).
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
