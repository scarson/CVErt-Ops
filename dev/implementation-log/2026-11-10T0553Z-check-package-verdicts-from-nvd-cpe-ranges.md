# Check package: verdicts from NVD CPE ranges

## What was built

- Task 3.4 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `ae67ed3`.
- `internal/check/cpe.go`: `CPERow` (CVE ID, `cpe_normalized`, the four `version*` bounds, `""` when absent) and `EvaluateCPERows(m, ver, rows)`, which decides one advisory's verdict for one product version from that advisory's `cve_cpe_matches` rows (design section 4.2). Every row is compared with `version.CheckNumeric`.
- `internal/check/verdict.go`: `rowVerdicts`, the combining rule of design section 4.1 (Affected if any row is; NotAffected only with a NotAffected row and no CannotEvaluate row; otherwise CannotEvaluate with the first CannotEvaluate row's reason), with the `Matched`, `Candidates`, `Ranges` and `Comparable` bookkeeping. `EvaluatePackageRows` and `EvaluateCPERows` both record their rows through it. `reasonFor` moved here from `packages.go`, since both sources use it. The package tests are unchanged and pass.

## Decisions and gotchas

- Stored shapes, confirmed in the code: the NVD adapter sets `cpe_normalized` to the criteria string lower-cased (`internal/feed/nvd/adapter.go`), and merge writes each absent bound as NULL through `dbutil.NullString` (`internal/merge/pipeline.go` `replaceVersionRanges`). The store layer must read NULL as `""` into `CPERow`.
- The row's own version is `splitCPE(row.CPE)[5]`, so an escaped colon in the vendor (`foo\:bar`) does not shift it. A CPE that does not split into 13 components is `invalid_range`.
- Row rules: `*` (or empty) with a bound gives `Introduced` = the start bound or `"0"`, `Fixed` = `versionEndExcluding`, `LastAffected` = `versionEndIncluding`; `versionStartExcluding` is an inclusive `Introduced`. A literal version with no bound gives `Introduced` = `LastAffected` = that version. `*` with no bound, and `-` with or without bounds, are `no_version_bounds`.
- Shapes the design does not describe answer `invalid_range` and never a guess: both start bounds set, and a literal version component with bounds. Both end bounds set is passed to `CheckNumeric`, which reports `ErrInvalidRange`. A literal version component that is not dotted numbers (`1.2.3rc1`) is also `invalid_range`, from `CheckNumeric`.
- A row that gives no range (`no_version_bounds`, or the structural `invalid_range` cases) is recorded with an empty `Range` and `CheckNumeric`, which answers CannotEvaluate for any candidate, so fix reporting cannot clear a candidate against it. A test checks this.
- `Matched` carries evidence `nvd_cpe`, the row's CPE string, and the range as compared (so `Introduced` is `"0"` when the row has no start bound). `Candidates` holds `versionEndExcluding` of Affected rows only.
- `Tick` is called once per row, including rows that cannot be compared. When it refuses, the zero `Outcome` is returned.

## Quality checks

- The CPE tests failed first against a stub returning the zero `Outcome`; the package tests passed against the extracted `rowVerdicts` before `EvaluateCPERows` was written.
- `go test ./internal/check/ -count=1`: pass. The task's tests (`-run CPE`): 37 passing tests and subtests, 0 failures.
- `golangci-lint run ./internal/check/...`: 0 issues.
