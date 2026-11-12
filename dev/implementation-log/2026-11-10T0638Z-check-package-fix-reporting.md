# Check package: fix reporting

## What was built

- Task 3.7 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `cc2c772`.
- `internal/check/fix.go`: `PickFix(m, ver, candidates, order, ranges, cna)`, design section 7's four steps. Candidates are sorted with `order` (the ecosystem's order for a package item, `version.NumericOrder` for a CPE item). A nil order, no candidates, or a candidate the order cannot read gives no fix. Walking lowest first, a candidate passes when every `Bound` answers NotAffected for it and `cna` (when non-nil) reads neither `AffectedReading` nor `Indeterminate`. The first passing candidate is the fix.
- `fixMajorOf` gives `fix_major`: `same` when the version and the fix share their leading number, `different` when not, `unknown` when either has none.

## Decisions and gotchas

- Each candidate is compared with itself before sorting, so a lone candidate the order cannot read (a single `1.1rc1` under the numeric order) gives no fix. Sorting alone never calls the order for one element.
- Candidates the order reads as equal (`1.2` and `1.2.0` numerically) are checked once, in the first spelling given, so the reported fix is a string a source wrote.
- A candidate's checks stop at the first range that rejects it, and the `cna` func is called only after every range has passed. `m.Tick` is called once per range check and once per `cna` call; a refused tick returns no fix.
- The leading number is read after a dpkg/RPM epoch (`1:`), then one `v` or `V` before a digit (Go module versions such as `v1.2.3`), then a PEP 440 epoch (`1!`). The design says "after any epoch"; without the PEP 440 case, PyPI `1!2.0` and `1!3.0` would both read 1 and report `same`. Leading zeros are dropped and the digits compared as strings, so values longer than any integer type compare correctly.
- `1:abc` has no leading number after its epoch and reads `unknown`; a single regular expression with an optional epoch group would backtrack and read the epoch `1` as the number, so the epoch is removed in its own step.
- `PickFix` returns a pointer to a fresh string on each call, so a caller changing one answer's `fix_major` cannot change another's.

## Quality checks

- The tests failed first to compile with `PickFix` undefined. Two tests drive `PickFix` with the `Candidates` and `Ranges` of real `EvaluatePackageRows` and `EvaluateCPERows` outcomes, one with the `cna` func built from `ReadCNAEntries`.
- Break tests (each mutation applied alone, then restored): removing de-duplication, the self-comparison, the CannotEvaluate rejection, the Indeterminate rejection, either epoch removal, the `v` removal, the leading-zero trim, the meter check, or the sort each fail a named test. The self-comparison mutation at first survived, because the numeric range also rejected `1.1rc1`; the no-minimum tests now use a range that accepts every candidate.
- `go test ./internal/check/ -count=1 -race`: pass. The task's tests: 8 tests with 30 subtests passing, 0 failures.
- `golangci-lint run ./internal/check/...`: 0 issues.
