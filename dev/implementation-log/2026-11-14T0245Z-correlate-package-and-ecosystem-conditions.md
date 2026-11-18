# Correlate package and ecosystem conditions and add exact package match

## What was built

MATCH-2 plan Task 2.3 (design sections 4.1, 4.2 and 5.1). `affected.ecosystem` and `affected.package` conditions compile to CVE-ID sets in the new `internal/alert/dsl/sets.go`:

- An `eq`/`in` ecosystem condition is `cves.cve_id IN (SELECT cap.cve_id FROM cve_affected_packages cap WHERE ...)` with one ecosystem line. A `neq`/`not_in` condition stays a correlated `NOT EXISTS` with the same line.
- A package condition is a set holding its own predicate and, in an `and` rule, one ecosystem line per `eq`/`in` ecosystem condition. Those ecosystem conditions then emit nothing on their own. Package conditions are not correlated with each other. Under `or` every condition is its own set.
- `affected.package` gains `eq` and `in`: the index expression `ecosystem.FoldedNameSQL("cap.ecosystem", "cap.package_name")` compared to values folded in Go, as one arm when the correlated ecosystem values are all `PyPI` or contain no `PyPI`, and otherwise as a `PyPI` arm and a non-`PyPI` arm. Each folded list is de-duplicated.
- Ecosystems compare exactly (`cap.ecosystem = ANY(?)`), with a `LIKE ANY(?)` release arm only for values whose base takes a suffix (new `ecosystem.TakesSuffix`); the release patterns are `escapeLike(v) + ":%"`.
- With candidate IDs, each set carries `cap.cve_id = ANY(?)` inside it (pitfall DB-27); `NOT EXISTS` does not need them.

`affectedSQL`, `affectedEcosystemSQL` and `affectedPackageSQL` are removed from `compiler.go`; `Compile` computes the rule's correlation once (`correlationFor`) and asks `affectedPredicate` for each affected condition.

## Key decisions

- **Predicates stay pure.** Every list, pattern and `pq.Array` is built in `Compile`; `packageSet` builds new slices per call and only reads the lines and candidate IDs.
- **Folded lists are de-duplicated with a map**, since an `in` list can hold tens of thousands of names inside the 1 MiB request limit.
- **Ecosystem lists are bound as written**, without de-duplication, and a JSON `null` list binds an empty array (the same normalisation as `setSQL`), so `in null` still matches nothing and `not_in null` everything.
- `textOpsNoRegex` had only `affected.package` as a user and is replaced by `packageOps`.

## Gotchas

- An `and` rule with two `eq`/`in` ecosystem conditions beside a package condition now needs both on the package's row; Task 2.4 refuses the shape that can never match.
- No existing integration test depended on uncorrelated matching: `internal/alert/ecosystem_match_test.go` has ecosystem conditions without package conditions, and `internal/store/dsl_executor_test.go` has no affected conditions.

## Quality checks

- Rewritten for the new SQL (they asserted `lower(cap.ecosystem) LIKE ANY` or `EXISTS`): `TestCompile_AffectedEcosystemEq`, `TestCompile_AffectedEcosystemIn`, `TestCompile_AffectedEcosystemMatchesExactOrSuffixed`, `TestCompile_AffectedEcosystemEscapesLikeMetacharacters` in `internal/alert/dsl/dsl_test.go`; they now assert the set shape and every bound array.
- Added `internal/alert/dsl/sets_test.go` (the plan's shape cases, folding, de-duplication, candidate lines per set, banned shapes) and `TestTakesSuffix`; `TestWhere_IsDeterministicAcrossCalls` gains a rule with package sets.
- `go test ./internal/alert/dsl/... ./internal/ecosystem/... ./internal/ai/... -count=1`: pass.
- `go test ./internal/alert/... ./internal/store/... -count=1 -run 'Ecosystem|DSL'`: pass.
- golangci-lint v2.15.0 on `./cmd/... ./internal/... ./migrations/...`: 0 issues.
