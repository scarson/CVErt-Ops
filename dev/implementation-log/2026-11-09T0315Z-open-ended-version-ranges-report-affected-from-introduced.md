# Open-ended version ranges report affected from introduced

Commit `87d1cb0` on `feat/open-ended-version-ranges`. Plan: `dev/plans/2026-11-08-cve-range-data-batch-plan.md`, Task 1.1 (report ranges with no upper bound).

## What was built

- `version.Check` and `version.CheckNumeric` accept a `Range` with neither `Fixed` nor `LastAffected`. A version at or above `Introduced` is `Affected`, a version below it is `NotAffected`, and `Introduced: "0"` is `Affected` for every valid version. This is the OSV schema's definition of a range with no upper bound.
- A missing or malformed `Introduced`, and a range with both `Fixed` and `LastAffected`, still return `CannotEvaluate` with `ErrInvalidRange`. An invalid version still returns `CannotEvaluate` with `ErrInvalidVersion`.
- `PLAN.md` §9.2 (version comparison rules) states the same behaviour.

## Key decisions

- **`Range.upperBound` returns a third value, `bounded`,** so `check` and `validateRange` share one definition of "has an upper bound".
- **`check` returns `Affected` only after `validateRange` and the `Introduced` comparison have run,** so an open-ended range cannot skip validation or report a version below `Introduced` as affected.

## Gotchas

- `internal/feed/ghsa/adapter.go` still writes `Introduced: "0"` with an empty `Fixed` when an advisory has no patched version, whatever its real upper limit is. That shape now reads as `Affected` for every valid version. The entry `2026-11-07T0150Z-internal-version-package.md` (first version of the package) rejected open-ended ranges for this reason. No package outside `internal/version` imports it yet, so no result changes today. The GHSA range parser in Phase 2 of the plan replaces those rows, and it must land before anything calls `Check` on stored GHSA data.
- `TestCheck_NoUpperBoundStillValidatesVersion` passed before the implementation, because both of its inputs were already rejected with the error it expects. It guards against the open-ended path skipping validation, and the other two new tests are the ones that failed first.

## Quality checks

- `go test ./internal/version/ -count=1`: before the implementation, `TestCheck_NoUpperBound` and `TestCheckNumeric_NoUpperBound` failed with `invalid range: no upper bound`. After it, the package passes. No database or Docker is needed.
- `golangci-lint run ./internal/version/...`: 0 issues.
- The full suite did not run for this task. The plan runs it at the end of the phase.
