# Check package: reading CNA version entries as segments

## What was built

- Task 3.5 of `dev/plans/2026-11-09-version-check-endpoint-plan.md` (version check endpoint, Phase 3), commit `d251fe2`.
- `internal/check/cna.go`: the plan's `CNAVersion`, `CNAChange`, `Reading` (`NoStatement`, `NoVersionInfo`, `Indeterminate`, `AffectedReading`), `readEntry` and its supporting functions, as the plan writes them. `CNARow` (CVE ID, vendor, product, decoded `versions`), `CNAResult` (strongest reading, fix candidates, matched segments), `ReadCNAEntries(m, ver, rows)` and `CNARangeCount(rows)`.
- Design section 4.3 is the authority: CNA data reports Affected, Indeterminate, no version information or no statement for a version, never Not affected.

## Decisions and gotchas

- The JSON tags match `internal/feed/interface.go` `CNAVersion` (`version`, `less_than`, `less_than_or_equal`, `status`, `version_type`, `changes`, `at`). A test marshals `feed.CNAVersion` values and decodes them, and decodes a literal stored array.
- `Matched` for CNA, which the plan leaves open: `readEntry`'s internal `reading` carries the segment that contains the version, and each Affected element adds `Matched{Evidence: "cna", Introduced: <segment start>, Fixed: <end if exclusive>, LastAffected: <end if inclusive>}`. An open end (free text `>= x`) sets neither. No reading changes because of this.
- A single-version entry whose version ends in `.*` (such as `8.1.*` with no upper bound and no changes) keeps the stored value as its upper edge. That value cannot be read, so versions at or above `8.1` read Indeterminate. Taking the edge from the normalised lower bound (`8.1`) would read `8.1.5` as no statement, although the entry names the whole 8.1 line. A break test confirmed that reading fails the test for `8.1.5`.
- `buildSegments` checks each `at` with the order before sorting, because a sort of one change compares nothing and would never find an unreadable `at`.
- A start of `"0"` is below every version in `contains`, `isBelow` and `atStart`, as `version.Check` reads an introduced `"0"`. Ends are compared as stored. A break test confirmed the `0.0.0-alpha` case catches its removal.
- `ReadCNAEntries` checks `m.Err()` before each element and after the loop, and returns the zero `CNAResult` once it is non-nil. Every comparison inside `readEntry` ticks the meter, including the `at` checks and the sort.

## Quality checks

- The tests failed first against stubs returning zero values (65 failing cases), then passed against the implementation.
- `go test ./internal/check/ -run CNA -count=1`: pass. 73 `TestReadCNAEntry` cases (every version of every row of the plan's table, then design section 4.3 rows and rules the plan rows do not reach), 8 `TestReadCNAEntries`, 4 `TestCNARangeCount`, 3 `TestReadCNAEntriesMeter`, 2 `TestCNAVersionDecodesStoredJSON`; 0 failures.
- `go test ./internal/check/ -count=1`: pass.
- `golangci-lint run ./internal/check/...`: 0 issues.

## Conflicting changes at one version

Two changes whose `at` values compare equal and whose statuses differ (an empty status read as `unknown`) made the reading depend on input order: `{1.0, lt 3.0, affected}` with changes to `affected` and to `unaffected` at 2.0 read `2.0` as no statement in one order and Affected in the other. `buildSegments` now reports such an entry as unsortable, so it reads Indeterminate at or above a readable lower bound and no statement below it, in both orders. Repeated changes with the same status still read as segments. Eight cases cover both input orders at 2.0, 1.5 and 0.5, and the same-status repeat at 1.5 and 2.0. The four cases at 2.0 and 1.5 failed first. Commit `fix(check): read conflicting changes at one version as unsortable`. `go test ./internal/check/ -count=1` passes and `golangci-lint run ./internal/check/...` reports 0 issues.
