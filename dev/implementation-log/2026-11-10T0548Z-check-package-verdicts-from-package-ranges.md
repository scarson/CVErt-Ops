# Check package: verdicts from package ranges

## What was built

- Task 3.3 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `e7d2e87`.
- `internal/check/verdict.go`: the types every verdict source shares, as the plan writes them: `Verdict` (zero value `CannotEvaluate`), `Reason`, `Matched`, `Outcome`, `Bound`, and `workMeter` (checks the request's context every 1,000 ticks; `Err` reads the context when asked). It also declares a `Reason` constant for each of the 13 values of design section 11's `reason` enumeration, for the later tasks.
- `internal/check/packages.go`: `PackageRow` and `EvaluatePackageRows(m, ecosystem, ver, rows)`, which decides one advisory's verdict for one package version from that advisory's `cve_affected_packages` rows (design section 4.1).

## Decisions and gotchas

- Stored `range_type` values, from the OSV and GHSA adapters: `ECOSYSTEM`, `SEMVER` and `GIT` as OSV sends them, `ECOSYSTEM` from GHSA, `VERSIONS` for rows built from an OSV `versions` list (a single version as `introduced` = `last_affected`, or no bounds). The comparison is exact and upper-case, as in `merge.rangeClass` and the OSV adapter. Another spelling falls to `version.Check`, which refuses commit hashes, so it cannot produce "not affected".
- `GIT` rows are skipped when the advisory has any other row. With only `GIT` rows the outcome is `commit_ranges_only`. Skipped rows get no `Bound` and no `Tick`.
- A `SEMVER` row is read with `version.CheckSemver` when `ecosystem.OrdersBySemver` is false. Design 4.1's rows are applied in order, so this includes ecosystems with no comparator: a `SEMVER` row in `Root:x` is read as SemVer, and an `ECOSYSTEM` row there is `unknown_version_scheme`.
- Combining: Affected if any row is; NotAffected only with at least one NotAffected row and no CannotEvaluate row; otherwise CannotEvaluate. A CannotEvaluate advisory's reason is that of its first CannotEvaluate row in row order. Reason is empty for Affected and NotAffected.
- `Ranges` holds one `Bound` per compared row, including rows that answered CannotEvaluate, each with the check that row used. Fix reporting (Task 3.7) re-checks candidates through them, which is how the `(0, A)` and `("", B)` shape gives Affected with no fix claimed: candidate A against the `("", B)` bound is CannotEvaluate. A test documents this.
- `Candidates` holds the `fixed` bound of each Affected row; `last_affected` is never a candidate (design section 7).
- When `Tick` refuses, `EvaluatePackageRows` returns the zero `Outcome` (CannotEvaluate); the caller discards it and reports `m.Err()`.
- With no rows the outcome is CannotEvaluate with an empty reason; the caller is not expected to call it without rows.

## Quality checks

- The tests failed first against a stub returning the zero `Outcome`.
- Break-test of `workMeter.Err` (plan's verify-first note): with `Err` returning only the stored error, the "Err reports cancellation before any tick" and "cancelled context below 1,000 rows" tests failed; restored, they pass.
- `go test ./internal/check/ -count=1`: pass. The task's tests: 44 passing tests and subtests, 0 failures.
- `golangci-lint run ./internal/check/...`: 0 issues.
