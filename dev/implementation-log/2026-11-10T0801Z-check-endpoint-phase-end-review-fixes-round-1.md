# Check endpoint phase-end review fixes, round 1

## What was built

Six fixes from the Phase 3 phase-end reviews (pitfall check, plan check, security review) of `POST /api/v1/orgs/{org_id}/check`, the version check endpoint of `dev/plans/2026-11-09-version-check-endpoint-plan.md`. One commit each, test first.

- `3781bec` fix(check): `parseCPE` in `internal/check/input.go` refuses a CPE with any character outside printable ASCII (0x21-0x7E) as `invalid_cpe`, before lower-casing. A CPE 2.3 formatted string is printable ASCII, and Go's `strings.ToLower` and PostgreSQL's `lower()` (which folds stored CNA names) can disagree outside ASCII, so a key could miss its stored CNA rows and read as not affected.
- `1b60603` fix(check): a `SEMVER` row in an ecosystem whose native order is not SemVer, and that has a comparator (`version.Supported`), is read in both orders (`checkBothOrders` in `internal/check/packages.go`): Affected if either order contains the version, NotAffected only if both exclude it, otherwise CannotEvaluate with the error of an order that could not evaluate, the native order's when both could not. Ecosystems with no comparator (`Root:*`, `GitHub Actions`) keep the SemVer reading. PLAN.md section 9.2 requires native ordering; before this, Debian `2.0.0-1` against `SEMVER [2.0.0, 3.0.0)` and Maven `1.0-sp` against `SEMVER [1.0, 2.0)` were not affected. The combined check is the row's `Bound.Check`, so `PickFix` rejects a candidate either order still reports.
- `81cd23e` fix(api): `checkComponentsHandler` reads, decodes, counts and parses the body before taking a check slot. `runCheck` holds the slot for `ReadCheckCandidates` and `EvaluateWithLimits` only and releases it before the response is written. Before the 200 response, a 30-second write deadline (`checkWriteTimeout`) is set through `http.ResponseController`; `http.ErrNotSupported` is ignored and any other error logged as a warning. The metrics middleware's `statusWriter` has `Unwrap`, so the deadline reaches the connection.
- `0968e23` fix(store): `readKeyRows` in `internal/store/check.go` runs each lookup under its own context and cancels it before returning `ErrCandidateLimit`, so pgx stops the statement instead of reading every remaining row (up to 50,001 per key) when the rows are closed.
- `cf01f1c` test(store): `TestReadCheckCandidates_Packages` also calls the exported `ReadCheckCandidates` (default limits) and requires the same candidates as the test-only `ReadCheckCandidatesWith` (testing-pitfalls section 7).
- `3d8243a` test(check): the CVE-2024-7347 CNA entry in `internal/check/cna_test.go` (`cnaNginx7347`, `{1.25.0, lt 1.27.1}`) and the matching comment in `combine_test.go` now say it is the plan's simplified shape; the real record is `{1.5.13, lt *, affected, semver}` with changes to unaffected at 1.26.2 and 1.27.1. Data and results unchanged.

## Decisions and gotchas

- Design section 4.1's `SEMVER` row still reads "Compared as SemVer, through a new `version.CheckSemver`. A version SemVer cannot read is cannot evaluate." That no longer holds where the ecosystem has a comparator: a version only the native order can read is now Affected when the native order contains it (Alpine `2.5.0_rc1` against `SEMVER [2.0.0, 3.0.0)`). The design text was not edited here.
- Versions used in the `SEMVER` tests were chosen by probing `version.CheckSemver` and `version.Check`: `2.0.0-1` is invalid in Alpine, `2.5.0_rc1` is valid in Alpine and invalid in SemVer, `2.0.0-1` as an Alpine bound makes the native range invalid (`invalid_range`), which shows the native error is preferred over SemVer's `invalid_version`.
- The fix-validation test uses two Debian `SEMVER` rows, `[0, 2.0.0)` and `[1.9.9, 2.0.0-1)`: candidate `2.0.0` is outside the second under SemVer and inside it under dpkg, so no fix is claimed. Before the change it reported `2.0.0`.
- Slot test: the handler is called directly with a body that blocks on its first read and a writer that blocks on its first write; `len(srv.checkSem)` must be 0 at both points. With all slots held, a malformed body now gets 400 rather than 503.
- Cancellation test: a pgx pool built from `tdb.AppURL` with a `QueryTracer` and `MaxConns = 1`, and one key with 3,000 package rows (merged through `merge.Ingest`) read under `RequestRows = 1`. Before the fix the tracer saw the packages statement end with `SELECT 3000` and no error; after it, the statement ends with an error, and the next read on the one-connection pool returns all 3,000 rows. The key needs more rows than pgx's read buffer holds: Go refuses a read after a passed deadline even when the kernel has the data, so only pgx's own buffer can still be read, and a small result already in it would complete. No `ContextWatcherHandler` is configured, so pgx's default closes the connection on cancellation; `database/sql` then discards it.
- The deferred `cancel()` alone would run after the deferred `rows.Close()` (defers run last in, first out), which is why `readKeyRows` also calls `cancel()` explicitly before returning `ErrCandidateLimit`.
- The direct `ReadCheckCandidates` assertion was checked with a break test: the exported method given a key limit of 0 failed the test; restored with `git checkout -- internal/store/check.go`.

## Quality checks

- `go test ./internal/check/ -count=1`: pass (581 tests and subtests in `-v` output).
- `go test ./internal/api/ -run 'Check|OpenAPI' -count=1`: pass, after fix B, after fix C and after fix F. No expectation in `check_integration_test.go` changed.
- `go test ./internal/store/ -run 'ReadCheck|Check' -count=1 -v`: pass, 17 tests.
- `golangci-lint run` on `./internal/check/...`, `./internal/api/...` and `./internal/store/...`: 0 issues each.
- Full suite not run.
