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

## Review fixes: x wildcards, inverted segments, conflicting changes

An independent review of `cna.go` found shapes that read as no statement where the entry condemns versions. Each fix follows the plan's rule that an input no rule covers is cannot evaluate. This commit replaces two earlier choices recorded above: the single-version `8.1.*` edge and the unsortable rule for conflicting changes.

- **`x` wildcards.** Maven and RPM read `2.x` as a version, so `{1.0, lt 2.x, affected, maven}` read 2.1 and 2.5 as no statement and 1.5 as Affected with candidate `2.x`. `lineWildcard` now accepts a final `.*`, `.x` or `.X`, for upper bounds, lower-bound normalisation (`2.x` becomes `2`), single-version entries and fix candidates. A change whose `at` is a line wildcard makes the entry unsortable.
- **Single-version line wildcards.** `{8.1.*, affected}` and `{8.1.x, affected}` are the segment from `8.1` to the wildcard end `8.2`: 8.1.5 reads Indeterminate (design 4.3's wildcard row), and 8.0.9, 8.2.0 and 9.0 read no statement. Before, 8.2.0 and 9.0 read Indeterminate, and under Maven `8.1.x` read 8.1.5 as no statement.
- **Inverted segments.** `{2.0, lt 1.0}`, `{2.10, lte 2.9}`, `{1.2.3, lt 1.2.3}` and `{1.0, lt 2.0, unaffected}` with a change to `affected` at 3.0 read no statement everywhere. A segment that is not `unaffected`, with readable edges, whose end is below its start (or equal and exclusive) now makes the entry Indeterminate for every version, as `version.Check` refuses the same shape. Inverted `unaffected` segments are left alone. Open and wildcard ends are not checked.
- **Conflicting changes.** Adjacent changes with equal `at` values collapse to one change, keeping a shared status and becoming `unknown` when the statuses differ. This runs before the inverted-segment check, so repeated changes leave no empty segment. `{1.0, lt 3.0, affected}` with changes to `affected` and `unaffected` at 2.0 reads 1.5 Affected with no candidate, 2.0 and 2.5 Indeterminate, and 0.5 no statement, in both input orders.
- Further cases pin current behaviour: `isBelow`'s "0" guard (removing it fails the `{0, lt 2.*}` / `0.0.0-alpha` case), free text `< 2.0`, `> 1.0`, `<= 2` and `= 1.0`, `{1.0, lt *}` with no changes, mis-cased `Affected` and `SemVer`, and a `*` lower bound with an upper bound (Indeterminate; whether `*` should read as `0` is open with Sam).
- Tests: 21 new cases failed first. `go test ./internal/check/ -count=1` passes (129 `TestReadCNAEntry` cases). `golangci-lint run ./internal/check/...` reports 0 issues.
- Follow-up commit `fix(check): read every wildcard-shaped CNA bound safely`: the inverted-segment check also covers a wildcard end, compared as exclusive, so `{3.0, lt 2.*, affected}` reads Indeterminate for every version where it read no statement. A bound or `at` ending in `.*`, `.x` or `.X` that is not a numeric line (`1.0-beta.x`, `2.0.rc.X`) is unreadable, where Maven and RPM read it as a version: `{1.0-beta.x, affected, maven}` read `1.0-beta.5` as no statement, and an upper bound or `at` of that shape gave a candidate. 8 new cases failed first; the package tests pass (145 `TestReadCNAEntry` cases), lint reports 0 issues.
