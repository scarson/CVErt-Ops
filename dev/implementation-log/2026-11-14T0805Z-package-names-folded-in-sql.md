# Package conditions fold the rule's values in the database

## What was built

| Feature | Files | Description |
|---|---|---|
| Fold helper | `internal/ecosystem/ecosystem.go` | `FoldedValueSQL(ecosystem, expr)` folds an expression as a name of that ecosystem (lower case; PyPI also collapses separators). `FoldedNameSQL` is built from it, and its text is unchanged, so `cve_affected_packages_check_idx` still matches it. |
| `eq` and `in` | `internal/alert/dsl/sets.go` (`packageMatch`, `foldedNameMatch`, `distinctValues`) | The values are bound as written and folded in SQL: `<folded name> = ANY(ARRAY(SELECT <fold>(v) FROM unnest(?::text[]) AS v))`. Exact duplicates are still dropped in Go. |
| Substring operators | `internal/alert/dsl/sets.go` | `contains`, `starts_with` and `ends_with` keep the value's case in the `ILIKE` pattern, which the database folds. |
| Tests | `internal/alert/dsl/sets_test.go`, `testdata/where.golden`, `internal/alert/package_match_test.go` | Compile tests pin values as written and the SQL fold; the golden file is regenerated; integration cases match a non-ASCII package name (`İzmir`) by `eq`, `in` (upper case) and `starts_with`. |
| Pitfall | `dev/implementation-pitfalls.md` DB-27 | The fold subquery is not a join to `unnest()`, with the measurement. |

## Key decisions

- **Fold in the database, not in Go.** Stored names are folded by PostgreSQL's `lower()` (the index expression), and the rule's values were folded by Go's `strings.ToLower`. The two agree on this project's images (`postgres:18-alpine`, `en_US.utf8`, libc), so no integration test fails before the change. They differ under a database whose `LC_CTYPE` is `C` (`lower()` folds ASCII only) and wherever Go's and the C library's Unicode tables differ, and then a rule does not match its own spelling. Found by the MATCH-2 code review (product-match-rules plan, Discoveries).
- **Shape checked on the kept full ingest (read-only, 2026-11-14), JIT and parallel query off:** three names with no ecosystem (two arms), whole corpus: bitmap OR of two index scans on `cve_affected_packages_check_idx`, 10 ms. npm and two names, whole corpus: the same index condition as before, 0.2 ms. One candidate CVE: the same nested-loop semi-join on `cve_id`, 0.08 ms. Each fold subquery is an InitPlan run once.

## Gotchas discovered

- Go's `strings.ToLower("İ")` is `"i"` (the simple Unicode mapping), the same as glibc's; a test built on that character does not separate the two folds.
- `assertSetShapeRules` bans `unnest(` anywhere in a set; it now removes the two fold subqueries before checking, since the ban targets lookups joined to `unnest()`.

## Quality checks

- `go test ./internal/alert/dsl/ ./internal/ecosystem/`: pass (compile tests failed first on the new contract).
- `go test ./internal/alert/ -run 'TestPackageMatch|ProductCandidateForm|TestOr'` and `./internal/store/ -run 'DSL|CheckPackageIndex'`: pass.
